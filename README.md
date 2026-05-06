# network-policy-enforcer

[![build](https://github.com/cloudnativedaysjp/network-policy-enforcer/actions/workflows/build.yaml/badge.svg)](https://github.com/cloudnativedaysjp/network-policy-enforcer/actions/workflows/build.yaml)

Lightweight nftables-based network policy enforcement agent for Kubernetes.
Designed for ZeroTrust lateral movement defense across internal network segments.

## Overview

`network-policy-enforcer` runs as a DaemonSet on each node.
On every refresh cycle it:

1. **Fetches the centrally-managed policy** from `POLICY_URL` (defaults to
   the InfoSec-maintained baseline at
   [`network-policy-enforcer-policy`](https://github.com/cloudnativedaysjp/network-policy-enforcer-policy))
   and writes it to `POLICY_FILE` as a cache.
2. **Discovers Pod IPs** in `TEAM_NS` via the Kubernetes API.
3. **Renders and applies** an nftables `inet` table per namespace with two
   drop rules:
   - per-source PPS rate limit on traffic to `destination_cidrs`,
   - per-source TCP SYN rate limit on intra-namespace Pod-to-Pod traffic
     (`peer_syn_rate_pps`; set to `0` to disable).

The agent is a single static Go binary (no `jq` / `curl` runtime dependency)
shipped on top of `alpine` with the `nftables` userspace tool. The image
intentionally **does not** ship a baked-in policy: the policy is always
fetched from `POLICY_URL` so the central baseline is the only source of truth.

## Container image

Multi-arch (linux/amd64, linux/arm64) images are published to GitHub Container
Registry by GitHub Actions on every push to `main` and on every `vX.Y.Z` tag.

| Tag | Source | Use case |
|---|---|---|
| `:latest` | latest commit on `main` | quickstart / dev clusters |
| `:sha-<short>` | every `main` push | pinning to a specific commit |
| `:vX.Y.Z` | SemVer release tag | stable release |

```sh
docker pull ghcr.io/cloudnativedaysjp/network-policy-enforcer:latest
```

### Local build

```sh
docker build -t network-policy-enforcer:dev .
```

Or, with a local Go toolchain:

```sh
go build -o enforcer ./cmd/enforcer
```

## Configuration

The policy is fetched from `POLICY_URL` on startup and on every refresh cycle.
The default points at the canonical baseline maintained by the InfoSec team:

```
https://raw.githubusercontent.com/cloudnativedaysjp/network-policy-enforcer-policy/refs/heads/main/policy.json
```

Updates merged into that repository's `main` branch propagate to every
enforcer in the fleet within one `REFRESH_INTERVAL` cycle (default 30s)
without a DaemonSet restart.

> [!IMPORTANT]
> The image does **not** ship a fallback policy. If `POLICY_URL` is
> unreachable at startup, the enforcer fails fast (`CrashLoopBackOff`).
> Once a policy has been fetched successfully, transient `POLICY_URL`
> failures are logged as `WARN` and the last-known-good policy remains in
> effect.
>
> Mounting a ConfigMap to override the cache file at `POLICY_FILE` does
> **not** survive the next refresh — the next successful fetch from
> `POLICY_URL` overwrites it. Per-cluster customization should be done by
> pointing `POLICY_URL` at a different file (subject to InfoSec approval).

### Policy file format

```json
{
  "version": "v2.4.0",
  "policy": {
    "name": "lateral-movement-baseline",
    "destination_cidrs": ["..."],
    "rate_limit_pps": 2000,
    "peer_syn_rate_pps": 100,
    "on_exceed": "drop"
  }
}
```

### Policy fields

| Field | Type | Description |
|---|---|---|
| `version` | string | Policy schema version |
| `policy.name` | string | Human-readable policy name |
| `policy.destination_cidrs` | string[] | List of destination CIDRs to enforce rate limiting on. |
| `policy.rate_limit_pps` | int | Packets per second threshold per source Pod IP for traffic to `destination_cidrs`. |
| `policy.peer_syn_rate_pps` | int | New TCP connection rate threshold per source Pod IP for **intra-namespace peer-to-peer** traffic (saddr ∈ team Pods AND daddr ∈ team Pods). Anti-port-scan / fanout heuristic. Set to `0` to disable. |
| `policy.on_exceed` | string | Action when rate is exceeded: `drop` |

### Environment variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `TEAM_NS` | Yes | — | Kubernetes namespace to discover Pod IPs from. Typically set via the downward API (`metadata.namespace`). |
| `POLICY_URL` | Yes (has a default) | `https://raw.githubusercontent.com/cloudnativedaysjp/network-policy-enforcer-policy/refs/heads/main/policy.json` | URL to fetch the policy JSON from. Setting this to an empty string is a fatal error — the image does not include a fallback policy. |
| `POLICY_FILE` | No | `/tmp/policy.json` | On-disk cache target for fetched policy. Must be writable by the container. |
| `APISERVER` | No | `https://kubernetes.default.svc` | Kubernetes API server URL. |
| `REFRESH_INTERVAL` | No | `30` | Seconds between policy refresh cycles. |

## Deployment

Deploy as a DaemonSet with `hostNetwork: true` and `NET_ADMIN` capability.
The agent requires:

- a ServiceAccount with `get`, `list`, `watch` permissions on `pods` in the
  target namespace,
- outbound HTTPS to `POLICY_URL`.

### DNS resolution

Since the DaemonSet uses `hostNetwork: true`, set `dnsPolicy: ClusterFirstWithHostNet`
so the agent can resolve `kubernetes.default.svc` via cluster DNS.

### Cleanup

On termination, the agent's `preStop` hook and signal handler delete the
nftables table, leaving no residual rules on the node.

## Logs

The agent emits structured stdout lines for operational visibility:

- `network-policy-enforcer <version> starting`
- `loaded policy: <name> (<version>)`
- `policy refresh ok (<N> endpoints)` — every refresh cycle
- `drop counter: {"packets":N,"bytes":M}` — destination_cidrs rule, every refresh cycle
- `peer-syn drops: {"packets":N,"bytes":M}` — peer_syn_rate_pps rule, every refresh cycle
- `policy reloaded (<md5>)` — when the fetched policy content changes
- `WARN: policy fetch failed, keeping last-known-good <file>: <err>` — transient `POLICY_URL` failure
- `policy load failed (<err>)` — on nftables apply error

Dropped packets are also logged to the kernel ring buffer with prefixes
`zte_drop:` (destination_cidrs rule) and `peer_syn_drop:` (peer_syn_rate_pps rule).

## Release

Cut a versioned image by pushing a SemVer tag:

```sh
git tag v2.4.0
git push origin v2.4.0
```

The `build` workflow publishes `:v2.4.0`, `:2.4`, and `:2.4.0` tags to GHCR and
the `release` job creates a corresponding GitHub Release. SemVer pre-release
tags (e.g. `v2.5.0-rc.1`) are auto-marked as Pre-release on the GitHub
Release page and do **not** update the `:latest` image tag.

## Repository layout

```
.
├── .github/workflows/build.yaml   # CI: multi-arch build & push to GHCR
├── cmd/
│   └── enforcer/
│       └── main.go                # CLI entrypoint (config + run loop)
├── internal/
│   ├── policy/                    # Policy struct, Load (file), Fetch (URL→file)
│   ├── k8s/                       # ServiceAccount-based Pod IP discovery
│   └── nft/                       # Render, Apply, DeleteTable, ReadCounter
├── Dockerfile                     # multi-stage: golang builder → alpine + nftables
├── go.mod                         # Go module (no external deps)
├── LICENSE
└── README.md
```
