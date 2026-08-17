# Official-base strategy

## Policy
1. **Primary upstream** = SagerNet official tags only (not whole-tree reF1nd merges).
2. **Always keep ours** (first-party, no reF1nd core overlays):
   - Smart (`protocol/group/smart*`)
   - AdaptivePool (`protocol/group/adaptive`)
   - eBPF-ours (`common/ebpf`, `protocol/ebpf`)
   - DirectOffload (route hooks + `adapter.DirectOffload`)
   - Provider (`provider/**`, `adapter/provider`) for smart node lists
3. **Never port**: reF1nd cilium eBPF stack; wholesale `route/rule` / `clashapi` overlays.

## Branch `adaptive/official-beta17`
- Base: pure `v1.14.0-beta.17`
- Version string: `1.14.0-beta.17-official-smart-ebpf`
- Build: `scripts/cross-build-official-smart-ebpf.sh` on Linux builder

## Deploy checklist
1. Binary size must be >50MB
2. `sing-box version` prints `official-smart-ebpf`
3. `sing-box check -c config.json` before restart
4. Log: `direct_offload=route+prefill+learn`
