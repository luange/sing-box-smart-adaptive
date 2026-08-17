# Official-base strategy

## Policy
1. **Primary upstream** = SagerNet official tags only (not whole-tree reF1nd merges).
2. **Always keep ours** (first-party):
   - Smart, AdaptivePool, eBPF-ours, DirectOffload
   - Provider (remote/local/inline)
   - LoadBalance, Pass
   - Connection history (`with_connection_history`)
3. **Never port**: reF1nd cilium eBPF stack as a whole-tree overlay.

## Branch `adaptive/official-beta17`
- Base: pure `v1.14.0-beta.17`
- Version: `1.14.0-beta.17-official-smart-ebpf`
- Default tags include `with_ebpf` (build script) and `with_connection_history` (DEFAULT_BUILD_TAGS_OTHERS)

## Feature enable notes
### connection_history
```json
{
  "experimental": {
    "connection_history": {
      "enabled": true,
      "path": "/var/lib/sing-box/connection-history.db",
      "retention": "168h"
    },
    "clash_api": { "external_controller": "127.0.0.1:9090" }
  }
}
```
API: `GET /history/summary|trend|connections|domains|...` when clash_api is up.

### eBPF splice (proxy zero-copy)
Requires kernel sockmap support. Config on eBPF inbound:
```json
"outbound_offload": {
  "splice": {
    "enabled": true,
    "accounting": true,
    "half_close": "close",
    "allow_outbound_types": ["direct", "ebpf", "socks", "http"],
    "max_pairs": 8192
  },
  "verdict": { "mode": "learn", "ttl": "5m", "promote_bypass": true },
  "dns_prefill": { "enabled": true, "ttl": "5m" }
}
```
Default on 115 keeps splice disabled for stability; path is fully wired when enabled.

### loadbalance / pass
Outbound types `loadbalance` and `pass` are registered. Strategies: `round-robin`, `consistent-hashing`, `sticky-sessions`.

## Build
```bash
./scripts/cross-build-official-smart-ebpf.sh
# VERSION=1.14.0-beta.17-official-smart-ebpf
```

## Deploy checklist
1. Binary size >50MB
2. `sing-box version` prints `official-smart-ebpf`
3. `sing-box check -c config.json`
4. Log: `direct_offload=route+prefill+learn`
