# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `policy.source_cidrs` policy field. Optional additional saddr filter
  applied on top of the per-namespace `team_pods` set; empty means "any
  team pod IP".
- `policy.destination_exclude_cidrs` policy field. Optional destination
  CIDRs to subtract from `destination_cidrs`. Lets operators express
  "all egress except cluster-internal CIDRs" by setting
  `destination_cidrs=0.0.0.0/0` and excluding the cluster CIDR.

### Changed

- The destination_cidrs rate-limit rule now matches
  `saddr ∈ team_pods ∧ (source_cidrs empty ∨ saddr ∈ source_cidrs) ∧
  daddr ∈ destination_cidrs ∧ (exclude empty ∨ daddr ∉ exclude)` instead
  of `saddr ∈ team_pods ∧ daddr ∈ destination_cidrs`.

### Fixed

- `rate_limit_pps` values `<= 0` (including the implicit `0` produced
  when the field is omitted from the upstream policy JSON) no longer
  blow up the entire `nft -f` apply. nftables rejects
  `limit rate over 0/second` as `Invalid argument`, which previously
  left the namespace with no table at all and recurring
  `policy load failed` log lines. The destination_cidrs rule is now
  skipped under those conditions and a `WARN` is logged so the
  disabled state is visible.

## [v2.4.0]

Initial release.

### Added

- Single static Go binary built on `alpine` + `nftables` (no `jq` / `curl`
  runtime dependency).
- DaemonSet-style per-namespace nftables `inet` table:
  - per-source PPS rate limit on traffic to `destination_cidrs`,
  - per-source TCP SYN rate limit on intra-namespace Pod-to-Pod traffic
    (`peer_syn_rate_pps`).
- Centrally-managed policy fetched from `POLICY_URL` on startup and on
  every `REFRESH_INTERVAL` cycle. The default points at
  [`network-policy-enforcer-policy`](https://github.com/cloudnativedaysjp/network-policy-enforcer-policy),
  the InfoSec-maintained baseline. The image deliberately ships no
  fallback policy — if the policy host is unreachable at startup the
  enforcer fails fast.
- Pod IP discovery via the Kubernetes API using the in-cluster
  ServiceAccount token (`get pods` on the target namespace).
- Hot-reload on fetched policy md5 change.
- Cleanup of the nftables table on `SIGTERM` / `SIGINT`.
- GitHub Actions workflow that builds multi-arch (linux/amd64, linux/arm64)
  images and publishes them to GHCR. SemVer tag pushes auto-create a
  GitHub Release; tags with a pre-release identifier (e.g. `v2.5.0-rc.1`)
  are auto-marked as Pre-release and do not update the `:latest` image tag.
