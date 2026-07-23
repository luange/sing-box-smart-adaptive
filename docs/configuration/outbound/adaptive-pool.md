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
    "manual_failure": "fallback"
  },
  "state": {
    "path": "adaptive-state-adaptive",
    "retention": "168h",
    "max_entries": 4096
  }
}
```

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
