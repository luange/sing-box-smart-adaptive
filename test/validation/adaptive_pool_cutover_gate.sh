#!/bin/sh

set -eu

API=${API:-http://127.0.0.1:9090}
PROXY=${PROXY:-http://127.0.0.1:8888}
STATUS=${STATUS:-/tmp/adaptive-cutover-gate.json}
MIN_GENERATION=${MIN_GENERATION:-2}

curl -fsS --max-time 5 "$API/adaptive-pools/v1/" > "$STATUS"

jq -e --argjson generation "$MIN_GENERATION" '
  ["HK", "US", "JP", "SG", "OT"] as $regions
  | [.adaptive_pools | to_entries[] | select(.key | endswith("-ADAPTIVE-SHADOW"))] as $pools
  | ($pools | length) == 5
  and all($regions[];
    . as $region
    | ($pools[] | select(.key == ($region + "-ADAPTIVE-SHADOW")) | .value) as $pool
    | $pool.shadow == true
    and $pool.generation >= $generation
    and $pool.candidate_count > 0
    and $pool.candidate_count == $pool.active_binding_count
    and $pool.missed_observations == 0
    and $pool.state_persistence_failures == 0
    and $pool.probe_scheduler_stalled_total == 0
    and $pool.probe_completed_total >= $pool.candidate_count
    and ([$pool.candidates[]? | select(.health == "healthy" and .breaker == "closed")] | length) >= 2
  )
' "$STATUS" >/dev/null

test "$(curl -x "$PROXY" -fsS --max-time 20 -o /dev/null -w '%{http_code}' https://www.google.com/generate_204)" = 204

jq '{ready:true, pools:[.adaptive_pools | to_entries[] | select(.key | endswith("-ADAPTIVE-SHADOW")) | {tag:.key,generation:.value.generation,candidates:.value.candidate_count,bindings:.value.active_binding_count,completed:.value.probe_completed_total,missed:.value.missed_observations,healthy:([.value.candidates[]? | select(.health == "healthy" and .breaker == "closed")]|length),degraded:([.value.candidates[]? | select(.health == "degraded")]|length)}]}' "$STATUS"
