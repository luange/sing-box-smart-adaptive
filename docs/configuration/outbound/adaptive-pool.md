---
icon: material/source-branch-sync
---

# AdaptivePool

AdaptivePool is an epoch-safe outbound decision engine. It consumes canonical
node snapshots from the sing-box provider boundary, keeps health and leases in
an independent state module, and resolves the selected `NodeHandle` back to an
epoch-local outbound only at execution time.

```json
{
  "type": "adaptive_pool",
  "tag": "adaptive",
  "providers": ["subscription"],
  "exclude_nodes": ["=subscription/retired-node"],
  "node_weights": [
    { "match": "Gcore", "weight": 0.25 },
    { "match": "=subscription/preferred-node", "weight": 2.0 }
  ],
  "shadow": true,
  "probe": {
    "url": "https://www.gstatic.com/generate_204",
    "coverage_interval": "10m",
    "timeout": "5s",
    "concurrency": 8,
    "queue_size": 4096
  },
  "policy": {
    "default": "adaptive",
    "strict_lease_ttl": "30m",
    "adaptive_lease_ttl": "10m",
    "max_leases": 8192,
    "max_attempts": 3,
    "attempt_timeout": "4s",
    "hedge_delay": "450ms",
    "manual_failure": "fallback",
    "ai_ipv6_policy": "block"
  },
  "state": {
    "path": "adaptive-state-adaptive",
    "retention": "168h",
    "max_entries": 4096
  }
}
```

## Manual candidate policy

`exclude_nodes` removes known-bad candidates by complete name or keyword. A
value beginning with `=` is an exact, case-insensitive match; other values are
case-insensitive substrings. `exclude` and `include` remain regular-expression
filters applied at the group boundary.

`node_weights` changes preference only among otherwise eligible candidates. A
weight below `1` lowers preference, `1` is neutral, and a weight above `1`
raises preference. It never re-enables an excluded, unhealthy, service-blocked,
or open-breaker node. Exact matches begin with `=`. If several keyword rules
match, the longest rule wins; an exact rule always wins. The status API exposes
`weight`, `weight_rule`, and `weight_rule_exact` for every candidate.

Service leases and switch audits include a 16-hex-character `session_id`.
It is a truncated keyed digest used only to correlate events for one anonymous
client/service affinity; it does not contain the source address, process,
username, destination, token, or credential.

`policy.ai_ipv6_policy` accepts `allow` (default) or `block`. `block` rejects
IPv6 destinations classified as ChatGPT/OpenAI, Claude, Gemini, Google account,
Apple and Microsoft OAuth domains join the same `browser_identity` lease as
ChatGPT, Claude, Gemini, Google login, and Cloudflare challenge traffic.
`ai_ipv6_policy: block` rejects IPv6 destinations in those identity families so
a dual-stack client can retry through IPv4.
It does not alter non-AI IPv6 traffic. This is a safety guard, not a substitute
for routing IPv6 through the transparent proxy.

## Rollout

Start with `shadow: true`. A promotable instance must have a non-zero
generation, non-empty candidates, matching active bindings, a live scheduler
owner, no missed observations, and no monotonic RSS/FD/queue growth. Promotion
changes only this outbound; it does not require gateway or DNS changes.

Use `sing-box tools adaptive-migrate` to convert legacy Smart groups. The tool
writes the exact original bytes to a rollback file before publishing the new
configuration. Unmapped legacy tuning fields are reported by name and are not
silently copied.

## Signed capability targets

Dynamic media URLs are credentials. They must come from an HTTPS manifest,
signed with Ed25519, and must never enter status, logs, errors, or persistent
state. Generate a key with `sing-box generate adaptive-manifest-key`. Serve a
short-lived specification with `sing-box tools adaptive-manifest serve`; the
server reloads both files on every request, so atomic file replacement rotates
keys without restarting it. Keep the private-key file mode at `0600`.

Supported service capabilities are `tls`, `auth_http`, `http`, `http3`, and `range`.
`http3` is available only in `with_quic` builds and rejects HTTP/2 fallback.

`builtin_youtube_tls` enables the fixed, credential-free YouTube TLS target.
`builtin_ai_service_tls` replaces it with five isolated service probes:
YouTube TLS, Google-backed Gemini TLS, unauthenticated OpenAI and Anthropic
model-list requests, and a browser-shaped ChatGPT web/WAF request. For the
unauthenticated probes, HTTP 401 proves that the service path is reachable.
For the web probe, 2xx is reachable and HTTP 403/451 or `cf-mitigated:
challenge` is blocked evidence. A strict majority of equal failures is treated
as a common target incident instead of penalizing every node. A 5xx response is
a target fault. No API key, cookie, response header, or query string is stored.
Builtin modes use one target per service and therefore require `quorum: 1`.
The two builtin modes and signed-manifest mode are mutually exclusive.

`builtin_exit_identity` uses the same scheduler and observation pipeline to
probe separate IPv4 and IPv6 identity endpoints. Raw addresses are converted
to process-local keyed tokens and are never exposed or persisted. Status shows
IPv4 baselines, IPv6 baselines, dual-stack nodes, changes, and saturated
rotating identities. All identity baselines disappear when the sing-box
process exits.

## API and dashboards

Clash-compatible proxy objects expose `adaptive_pool`, generation, revision,
mode, lease, queue, and candidate fields. Detailed control is under
`/adaptive-pools/v1`; `/adaptive-pools/v1/{name}/events` is an SSE status
stream. Selection and service overrides support control-revision CAS.

## Troubleshooting

- `generation: 0`: the runtime epoch was not published; do not promote.
- `candidate_count` differs from `active_binding_count`: reject the revision.
- growing `missed_observations`: evidence is stale or bypassing its epoch guard.
- repeated `delta_fallback_total`: the provider boundary is falling back to a
  full O(N) snapshot; inspect provider callback churn.
- capability refresh failures: keep endpoint probes active and fix the signed
  manifest; never substitute a static signed URL.

Retired state can be inspected with `sing-box tools adaptive-state-gc` (dry-run
by default). Pass every active state stem and use `--apply` only after review.
The Firefox acceptance script is `test/validation/adaptive_pool_firefox_acceptance.py`.
