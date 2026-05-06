// Package k8s provides minimal in-cluster Pod IP discovery via the
// ServiceAccount-mounted token. We deliberately avoid client-go to keep
// the binary small and the dependency surface zero — the only operation
// the enforcer needs against the API server is "list Pods in a namespace".
package k8s

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	DefaultTokenPath  = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	DefaultCACertPath = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

// Client is a thin wrapper around an HTTP client configured with the
// in-cluster ServiceAccount CA, scoped to a single API server URL.
type Client struct {
	http      *http.Client
	apiServer string
	tokenPath string
}

// NewClient constructs a Client that authenticates with the
// ServiceAccount token at tokenPath and verifies the API server using
// the CA bundle at caCertPath.
func NewClient(apiServer, caCertPath, tokenPath string, timeout time.Duration) (*Client, error) {
	caBytes, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("read sa ca.crt: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caBytes) {
		return nil, fmt.Errorf("invalid sa ca.crt")
	}
	return &Client{
		http: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: pool},
			},
		},
		apiServer: strings.TrimRight(apiServer, "/"),
		tokenPath: tokenPath,
	}, nil
}

// PodIPs returns each Pod's `.status.podIP` for Pods in `ns`. Pods
// without an assigned IP are skipped.
func (c *Client) PodIPs(ns string) ([]string, error) {
	tokenBytes, err := os.ReadFile(c.tokenPath)
	if err != nil {
		return nil, fmt.Errorf("read sa token: %w", err)
	}
	url := fmt.Sprintf("%s/api/v1/namespaces/%s/pods", c.apiServer, ns)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(tokenBytes)))
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("apiserver returned status %d", resp.StatusCode)
	}
	var podList struct {
		Items []struct {
			Status struct {
				PodIP string `json:"podIP"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&podList); err != nil {
		return nil, fmt.Errorf("decode pod list: %w", err)
	}
	ips := make([]string, 0, len(podList.Items))
	for _, item := range podList.Items {
		if item.Status.PodIP != "" {
			ips = append(ips, item.Status.PodIP)
		}
	}
	return ips, nil
}
