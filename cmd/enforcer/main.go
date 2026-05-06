// Command enforcer is a small nftables-based per-namespace network policy
// enforcer.
//
// It runs as a DaemonSet, fetches the centrally-managed policy document
// from POLICY_URL on every refresh cycle, discovers Pod IPs in TEAM_NS
// via the Kubernetes API, and applies an `inet` table that rate-limits
// traffic from those Pods to the configured destination CIDRs and
// (optionally) caps the per-source intra-namespace TCP SYN rate.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/cloudnativedaysjp/network-policy-enforcer/internal/k8s"
	"github.com/cloudnativedaysjp/network-policy-enforcer/internal/nft"
	"github.com/cloudnativedaysjp/network-policy-enforcer/internal/policy"
)

const (
	defaultPolicyFile = "/tmp/policy.json"
	defaultPolicyURL  = "https://raw.githubusercontent.com/cloudnativedaysjp/network-policy-enforcer-policy/refs/heads/main/policy.json"
	defaultAPIServer  = "https://kubernetes.default.svc"
	defaultRefresh    = 30
	httpTimeout       = 10 * time.Second
)

type config struct {
	teamNS          string
	policyFile      string
	policyURL       string
	apiServer       string
	refreshInterval time.Duration
}

func main() {
	log.SetFlags(0)

	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("ERROR: %v", err)
	}

	// Initial fetch is required: there is no image-baked fallback. If the
	// policy host is unreachable at startup we fail fast so the DaemonSet
	// can be rescheduled or the misconfiguration surfaced via CrashLoop.
	if cfg.policyURL == "" {
		log.Fatalf("ERROR: POLICY_URL is required")
	}
	if err := policy.Fetch(cfg.policyURL, cfg.policyFile, httpTimeout); err != nil {
		log.Fatalf("ERROR: initial policy fetch from %s failed: %v", cfg.policyURL, err)
	}

	p, sum, err := policy.Load(cfg.policyFile)
	if err != nil {
		log.Fatalf("ERROR: %v", err)
	}
	log.Printf("network-policy-enforcer %s starting", p.Version)
	log.Printf("loaded policy: %s (%s)", p.Spec.Name, p.Version)

	table := nft.TableName(cfg.teamNS)
	installSignalHandler(table)

	client, err := k8s.NewClient(cfg.apiServer, k8s.DefaultCACertPath, k8s.DefaultTokenPath, httpTimeout)
	if err != nil {
		log.Fatalf("ERROR: %v", err)
	}

	runLoop(cfg, table, sum, client)
}

func runLoop(cfg *config, table string, initialMD5 string, client *k8s.Client) {
	lastMD5 := initialMD5
	for {
		if err := policy.Fetch(cfg.policyURL, cfg.policyFile, httpTimeout); err != nil {
			log.Printf("WARN: policy fetch failed, keeping last-known-good %s: %v", cfg.policyFile, err)
		}

		p, sum, err := policy.Load(cfg.policyFile)
		if err != nil {
			log.Printf("policy load failed: %v", err)
			time.Sleep(cfg.refreshInterval)
			continue
		}
		if sum != lastMD5 {
			log.Printf("policy reloaded (%s)", sum)
			lastMD5 = sum
		}

		ips, err := client.PodIPs(cfg.teamNS)
		if err != nil {
			log.Printf("WARN: failed to fetch pod IPs: %v", err)
			time.Sleep(cfg.refreshInterval)
			continue
		}
		if len(ips) == 0 {
			time.Sleep(cfg.refreshInterval)
			continue
		}

		// Capture the previous cycle's accumulated counters before we
		// recreate the table — otherwise we'd always observe zeros from
		// the freshly initialized counters.
		prevCIDR := nft.ReadCounter(table, "zte_drop_total")
		prevPeerSYN := nft.ReadCounter(table, "peer_syn_drop_total")

		rules := nft.Render(table, ips, p)
		_ = nft.DeleteTable(table)
		if err := nft.Apply(rules); err != nil {
			log.Printf("policy load failed (%v)", err)
		} else {
			log.Printf("policy refresh ok (%d endpoints)", len(ips))
		}

		if prevCIDR != nil {
			b, _ := json.Marshal(prevCIDR)
			log.Printf("drop counter: %s", b)
		}
		if prevPeerSYN != nil {
			b, _ := json.Marshal(prevPeerSYN)
			log.Printf("peer-syn drops: %s", b)
		}

		time.Sleep(cfg.refreshInterval)
	}
}

func installSignalHandler(table string) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigCh
		_ = nft.DeleteTable(table)
		os.Exit(0)
	}()
}

func loadConfig() (*config, error) {
	teamNS := os.Getenv("TEAM_NS")
	if teamNS == "" {
		return nil, fmt.Errorf("TEAM_NS is required")
	}
	intervalSec, err := strconv.Atoi(getenv("REFRESH_INTERVAL", strconv.Itoa(defaultRefresh)))
	if err != nil {
		return nil, fmt.Errorf("invalid REFRESH_INTERVAL: %w", err)
	}
	return &config{
		teamNS:          teamNS,
		policyFile:      getenv("POLICY_FILE", defaultPolicyFile),
		policyURL:       getenv("POLICY_URL", defaultPolicyURL),
		apiServer:       getenv("APISERVER", defaultAPIServer),
		refreshInterval: time.Duration(intervalSec) * time.Second,
	}, nil
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
