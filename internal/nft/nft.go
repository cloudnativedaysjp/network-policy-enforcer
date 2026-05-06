// Package nft renders, applies, and inspects nftables rulesets via the
// `nft` userspace tool.
package nft

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/cloudnativedaysjp/network-policy-enforcer/internal/policy"
)

// Counter mirrors the relevant fields of `nft -j list counter`.
type Counter struct {
	Packets int64 `json:"packets"`
	Bytes   int64 `json:"bytes"`
}

// TableName returns a nftables-safe identifier for a Kubernetes namespace
// (hyphens become underscores so the output is a valid nftables identifier).
func TableName(ns string) string {
	return "netpol_enforcer_" + strings.ReplaceAll(ns, "-", "_")
}

// Render generates the nftables `inet` table for the given table name,
// pod IPs, and policy. The output is intended to be passed to `nft -f`.
func Render(table string, podIPs []string, p *policy.Policy) string {
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s {\n", table)
	fmt.Fprintln(&b, "  counter zte_drop_total {}")
	fmt.Fprintln(&b, "  counter peer_syn_drop_total {}")
	fmt.Fprintln(&b, "  set team_pods {")
	fmt.Fprintln(&b, "    type ipv4_addr")
	fmt.Fprintf(&b, "    elements = { %s }\n", strings.Join(podIPs, ", "))
	fmt.Fprintln(&b, "  }")
	fmt.Fprintln(&b, "  chain forward {")
	fmt.Fprintln(&b, "    type filter hook forward priority 0;")
	if p.Spec.PeerSYNRatePPS > 0 {
		fmt.Fprintf(&b,
			"    ip saddr @team_pods ip daddr @team_pods tcp flags & (syn|ack) == syn meter peer_syn_per_src size 65535 { ip saddr timeout 60s limit rate over %d/second } log prefix \"peer_syn_drop: \" counter name \"peer_syn_drop_total\" drop\n",
			p.Spec.PeerSYNRatePPS)
	}
	fmt.Fprintf(&b,
		"    ip saddr @team_pods ip daddr { %s } meter per_src size 65535 { ip saddr timeout 60s limit rate over %d/second } log prefix \"zte_drop: \" counter name \"zte_drop_total\" drop\n",
		strings.Join(p.Spec.DestinationCIDRs, ", "), p.Spec.RateLimitPPS)
	fmt.Fprintln(&b, "  }")
	fmt.Fprintln(&b, "}")
	return b.String()
}

// Apply atomically replaces the active ruleset for the table by writing
// the rendered nftables script to a temp file and invoking `nft -f`.
func Apply(rules string) error {
	tmp, err := os.CreateTemp("", "rules-*.nft")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(rules); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	cmd := exec.Command("nft", "-f", tmp.Name())
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft apply: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// DeleteTable best-effort removes the inet table; missing tables are
// not treated as errors so this is safe to call from cleanup paths.
func DeleteTable(table string) error {
	cmd := exec.Command("nft", "delete", "table", "inet", table)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	return cmd.Run()
}

// ReadCounter returns the current packets/bytes for a counter, or nil
// if the table or counter does not exist.
func ReadCounter(table, name string) *Counter {
	cmd := exec.Command("nft", "-j", "list", "counter", "inet", table, name)
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	var resp struct {
		Nftables []struct {
			Counter *struct {
				Packets int64 `json:"packets"`
				Bytes   int64 `json:"bytes"`
			} `json:"counter"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		return nil
	}
	for _, item := range resp.Nftables {
		if item.Counter != nil {
			return &Counter{
				Packets: item.Counter.Packets,
				Bytes:   item.Counter.Bytes,
			}
		}
	}
	return nil
}
