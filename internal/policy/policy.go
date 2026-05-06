// Package policy loads, fetches, and parses lateral-movement-baseline
// policy documents.
package policy

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// Policy is the on-disk schema of policy.json.
type Policy struct {
	Version string `json:"version"`
	Spec    Spec   `json:"policy"`
}

// Spec holds the actual rule parameters.
type Spec struct {
	Name             string   `json:"name"`
	Description      string   `json:"description,omitempty"`
	DestinationCIDRs []string `json:"destination_cidrs"`
	RateLimitPPS     int      `json:"rate_limit_pps"`
	PeerSYNRatePPS   int      `json:"peer_syn_rate_pps"`
	OnExceed         string   `json:"on_exceed"`
}

// Load reads and parses a policy file from disk. The returned md5 hex
// digest can be compared across calls to detect content changes for the
// hot-reload path.
func Load(path string) (*Policy, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("read policy file %q: %w", path, err)
	}
	return parse(data, path)
}

// Fetch downloads policy JSON from `url`, validates it, and writes it to
// `dest`. The caller is then expected to Load(dest) so the existing
// md5-change reload path applies uniformly to remote-fetched and locally-
// edited files. A corrupted upstream is rejected before persisting so the
// last-known-good file on disk is preserved.
func Fetch(url, dest string, timeout time.Duration) error {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch %s: HTTP %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read body from %s: %w", url, err)
	}
	if _, _, err := parse(body, url); err != nil {
		return err
	}
	if err := os.WriteFile(dest, body, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", dest, err)
	}
	return nil
}

func parse(data []byte, source string) (*Policy, string, error) {
	var p Policy
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, "", fmt.Errorf("parse policy from %s: %w", source, err)
	}
	sum := md5.Sum(data)
	return &p, fmt.Sprintf("%x", sum), nil
}

// Overrides carries per-deployment overrides for individual policy fields.
// A nil pointer / zero-length slice means "leave the upstream value alone";
// any non-empty value replaces the corresponding field in-place.
//
// This is the escape hatch for environments where the centrally-managed
// policy at POLICY_URL is too aggressive (e.g. shared-VPC EKS clusters
// where Pod IPs overlap with the policy's destination_cidrs). Operators
// scope overrides to a single DaemonSet via container env vars; the
// central baseline at POLICY_URL stays the source of truth for everything
// else.
type Overrides struct {
	DestinationCIDRs []string
	RateLimitPPS     *int
	PeerSYNRatePPS   *int
}

// Apply mutates p in-place, replacing fields for which the corresponding
// override is set. Designed to be called immediately after Load so the
// existing md5 reload path keeps observing the upstream policy content
// (the override is a constant; the fetched payload is what varies).
func (p *Policy) Apply(o Overrides) {
	if len(o.DestinationCIDRs) > 0 {
		p.Spec.DestinationCIDRs = o.DestinationCIDRs
	}
	if o.RateLimitPPS != nil {
		p.Spec.RateLimitPPS = *o.RateLimitPPS
	}
	if o.PeerSYNRatePPS != nil {
		p.Spec.PeerSYNRatePPS = *o.PeerSYNRatePPS
	}
}
