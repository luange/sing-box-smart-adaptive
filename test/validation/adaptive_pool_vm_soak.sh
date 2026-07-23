#!/bin/sh

set -eu

ROOT=${ROOT:-/root/adaptive-test}
API=${API:-http://127.0.0.1:19091}
AUTH=${AUTH:-adaptive-test-only}
PROXY=${PROXY:-http://127.0.0.1:19080}
TARGET=${TARGET:-http://10.254.40.118:19080/health}
DURATION_SECONDS=${DURATION_SECONDS:-604800}
SAMPLE_INTERVAL=${SAMPLE_INTERVAL:-60}
MAX_CONSECUTIVE_FAILURES=${MAX_CONSECUTIVE_FAILURES:-3}
MAX_RSS_GROWTH_KIB=${MAX_RSS_GROWTH_KIB:-131072}
MAX_FD_GROWTH=${MAX_FD_GROWTH:-32}
OUT=${OUT:-$ROOT/soak.csv}

business_check() {
  response=$(curl -x "$PROXY" -fsS --max-time 10 "$TARGET")
  [ "$response" = ok ] || [ "$(printf '%s' "$response" | jq -r '.ok // false')" = true ]
}

pid=$(pgrep -f "^$ROOT/sing-box run " | head -n 1)
test -n "$pid"
kill -0 "$pid"

rss_start=$(awk '/^VmRSS:/ {print $2}' "/proc/$pid/status")
fd_start=$(find "/proc/$pid/fd" -mindepth 1 -maxdepth 1 | wc -l)
started=$(date +%s)
deadline=$((started + DURATION_SECONDS))
failures=0

printf '%s\n' 'timestamp,rss_kib,threads,fd_count,queue_depth,state_entries,active_bindings,retired_bindings,missed_observations,business_ok' > "$OUT"

while [ "$(date +%s)" -lt "$deadline" ]; do
  now=$(date +%s)
  if ! kill -0 "$pid" 2>/dev/null; then
    echo "sing-box exited during soak" >&2
    exit 1
  fi
  status=$(curl -fsS --max-time 5 -H "Authorization: Bearer $AUTH" "$API/adaptive-pools/v1/ADAPTIVE-TEST/status")
  rss=$(awk '/^VmRSS:/ {print $2}' "/proc/$pid/status")
  threads=$(awk '/^Threads:/ {print $2}' "/proc/$pid/status")
  fd_count=$(find "/proc/$pid/fd" -mindepth 1 -maxdepth 1 | wc -l)
  business_ok=0
  if business_check; then
    business_ok=1
    failures=0
  else
    failures=$((failures + 1))
  fi
  queue=$(printf '%s' "$status" | jq -r '.probe_queue_depth')
  entries=$(printf '%s' "$status" | jq -r '.state_entries')
  active=$(printf '%s' "$status" | jq -r '.active_binding_count')
  retired=$(printf '%s' "$status" | jq -r '.retired_binding_count')
  missed=$(printf '%s' "$status" | jq -r '.missed_observations')
  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' "$now" "$rss" "$threads" "$fd_count" "$queue" "$entries" "$active" "$retired" "$missed" "$business_ok" >> "$OUT"

  test "$queue" -le 16
  test "$entries" -le 128
  test "$active" -le 2
  test "$rss" -le $((rss_start + MAX_RSS_GROWTH_KIB))
  test "$fd_count" -le $((fd_start + MAX_FD_GROWTH))
  if [ "$failures" -ge "$MAX_CONSECUTIVE_FAILURES" ]; then
    echo "business target failed $failures consecutive samples" >&2
    exit 1
  fi
  sleep "$SAMPLE_INTERVAL"
done

jq -n \
  --arg output "$OUT" \
  --argjson duration_seconds "$DURATION_SECONDS" \
  --argjson rss_start_kib "$rss_start" \
  --argjson rss_end_kib "$rss" \
  --argjson fd_start "$fd_start" \
  --argjson fd_end "$fd_count" \
  '{status:"passed", output:$output, duration_seconds:$duration_seconds, rss_start_kib:$rss_start_kib, rss_end_kib:$rss_end_kib, fd_start:$fd_start, fd_end:$fd_end}'
