#!/usr/bin/env bash
set -euo pipefail

api="${1:?usage: adaptive_pool_shadow_gate.sh API_BASE POOL_NAME}"
pool="${2:?usage: adaptive_pool_shadow_gate.sh API_BASE POOL_NAME}"

case "$api" in
  http://127.0.0.1:*|http://localhost:*|https://127.0.0.1:*|https://localhost:*) ;;
  *) echo "refusing non-loopback Clash API" >&2; exit 2 ;;
esac

encoded_pool="$(python3 - "$pool" <<'PY'
import sys
from urllib.parse import quote
print(quote(sys.argv[1], safe=""))
PY
)"
status="$(curl --fail --silent --show-error --max-time 5 "$api/adaptive-pools/v1/$encoded_pool/status")"

jq -e '
  .shadow == true and
  .generation > 0 and
  .candidate_count > 0 and
  .candidate_count == .active_binding_count and
  .probe_owner_epoch > 0 and
  .probe_owner_generation > 0 and
  .missed_observations == 0 and
  .state_persistence_failures == 0 and
  ([.candidates[]? | select(.identity_stable == true)] | length) > 0 and
  ([.candidates[]? | select(.health == "healthy" and .breaker == "closed")] | length) > 0
' >/dev/null <<<"$status"

jq '{ready:true,shadow,generation,candidate_count,active_binding_count,probe_owner_epoch,probe_owner_generation,missed_observations,delta_applied_total,delta_fallback_total}' <<<"$status"
