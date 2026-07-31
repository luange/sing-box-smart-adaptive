#!/usr/bin/env sh
# AdaptivePool release gates — run before packaging / NAS push.
set -eu
ROOT="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "== unit gates =="
go test ./protocol/group/adaptive/ -count=1 -timeout 5m \
  -run 'Gate|ThousandPublish|PlanFiltering|TransportPurpose|SwitchMargin|SwitchCooldown|Smoothed|CapabilityProfile|ExclusionReasons|DualStack|PlanDualStack|ReadFromLocal|AIServiceCapabilityIsSealed|SealedProbe|BuiltinAI|StrictAffinityFailureRetains'

echo "== race gates =="
go test ./protocol/group/adaptive/ -count=1 -timeout 10m -race \
  -run 'Gate|ThousandPublish|PlanFiltering|TransportPurpose|ReloadHeap|DualStack|PlanDualStack'

echo "== heap reload gate (1000 cycles) =="
HEAP_OUT="${ADAPTIVE_HEAP_OUT:-$HOME/Documents/Codex/2026-07-17/new-chat-3/outputs/adaptive-heap-gate-latest}"
mkdir -p "$HEAP_OUT"
ADAPTIVE_HEAP_OUT="$HEAP_OUT" go test ./protocol/group/adaptive/ -count=1 -timeout 10m -run 'TestGateReloadHeapBounded' -v
echo "heap profiles: $HEAP_OUT"
if [ -f "$HEAP_OUT/adaptive-reload-1000.pb.gz" ]; then
  echo "-- pprof inuse_space top (1000) --"
  go tool pprof -top -sample_index=inuse_space -unit=kb "$HEAP_OUT/adaptive-reload-1000.pb.gz" 2>/dev/null | head -15 || true
fi

echo "== related packages =="
go test ./experimental/clashapi/ ./protocol/group/ ./option/ -count=1 -timeout 5m

echo "== vet =="
go vet ./protocol/group/adaptive ./option ./adapter

echo
echo "PASS: all automated release gates green (unit + race + heap + vet)."
echo "Optional full-process RSS still on target VM with packaged binary."
echo "See: Documents/Codex/2026-07-17/new-chat-3/outputs/adaptive-release-gates-20260730.md"
