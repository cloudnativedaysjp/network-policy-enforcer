# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [v2.5.0-rc.1]

### Fixed

- `rate_limit_pps` values `<= 0` (including the implicit `0` produced
  when the field is omitted from the upstream policy JSON) no longer
  blow up the entire `nft -f` apply. nftables rejects
  `limit rate over 0/second` as `Invalid argument`, which previously
  left the namespace with no table at all and recurring
  `policy load failed` log lines. The destination_cidrs rule is now
  skipped under those conditions and a `WARN` is logged so the
  disabled state is visible.

## [v2.5.0-rc.0]

Pre-release. See [#1](https://github.com/cloudnativedaysjp/network-policy-enforcer/issues/1)
for the original report and design discussion.

### Added

- Per-namespace policy overrides via container env vars. Each override, when
  set, replaces the corresponding field of the fetched policy in-place after
  every refresh cycle. The central baseline at `POLICY_URL` remains the
  source of truth; overrides are scoped to a single DaemonSet container
  and require no manifest restructuring beyond adding env vars.
  - `POLICY_DESTINATION_CIDRS` — comma-separated CIDRs.
  - `POLICY_RATE_LIMIT_PPS` — integer.
  - `POLICY_PEER_SYN_RATE_PPS` — integer; `0` disables the rule.
- `policy.source_cidrs` and `policy.destination_exclude_cidrs` policy fields,
  with corresponding `POLICY_SOURCE_CIDRS` and `POLICY_DESTINATION_EXCLUDE_CIDRS`
  env-var overrides. The destination_cidrs rate-limit rule now matches traffic
  where `saddr ∈ team_pods ∧ (source_cidrs empty ∨ saddr ∈ source_cidrs) ∧
  daddr ∈ destination_cidrs ∧ (exclude empty ∨ daddr ∉ exclude)`. This lets
  operators express "all egress except cluster-internal CIDRs" by setting
  `destination_cidrs=0.0.0.0/0` and excluding the cluster CIDR.
- `POLICY_DESTINATION_EXCLUDE_CIDRS` distinguishes "unset" from "explicitly
  empty": setting the env var to an empty string clears any upstream-provided
  exclude list, while leaving it unset preserves the upstream value.

### Changed

- `internal/policy.Policy` gains an `Apply(Overrides)` method. The
  `policy.Overrides` struct uses pointer / zero-length-slice semantics so
  callers can distinguish "leave upstream value alone" from "explicitly
  set to zero / empty".

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
