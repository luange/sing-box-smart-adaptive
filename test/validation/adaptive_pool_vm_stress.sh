#!/bin/sh

set -eu

ROOT=${ROOT:-/root/adaptive-test}
API=${API:-http://127.0.0.1:19091}
AUTH=${AUTH:-adaptive-test-only}
PROXY=${PROXY:-http://127.0.0.1:19080}
TARGET=${TARGET:-http://10.254.40.118:19080/health}

business_check() {
  response=$(curl -x "$PROXY" -fsS --max-time 5 "$TARGET")
  [ "$response" = ok ] || [ "$(printf '%s' "$response" | jq -r '.ok // false')" = true ]
}

pid=$(pgrep -f "^$ROOT/sing-box run " | head -n 1)
test -n "$pid"

rss_before=$(awk '/^VmRSS:/ {print $2}' "/proc/$pid/status")
threads_before=$(awk '/^Threads:/ {print $2}' "/proc/$pid/status")
fd_before=$(find "/proc/$pid/fd" -mindepth 1 -maxdepth 1 | wc -l)

for _ in $(seq 1 1000); do
  curl -fsS -X POST -H "Authorization: Bearer $AUTH" "$API/adaptive-pools/v1/ADAPTIVE-TEST/probes" > /dev/null
done
for _ in $(seq 1 200); do
  business_check
done
sleep 5

status=$(curl -fsS -H "Authorization: Bearer $AUTH" "$API/adaptive-pools/v1/ADAPTIVE-TEST/status")
rss_after=$(awk '/^VmRSS:/ {print $2}' "/proc/$pid/status")
threads_after=$(awk '/^Threads:/ {print $2}' "/proc/$pid/status")
fd_after=$(find "/proc/$pid/fd" -mindepth 1 -maxdepth 1 | wc -l)

test "$(printf '%s' "$status" | jq -r '.probe_queue_depth')" -le 2
test "$(printf '%s' "$status" | jq -r '.state_entries')" -le 128
test "$threads_after" -le $((threads_before + 2))
test "$fd_after" -le $((fd_before + 4))
test "$rss_after" -le $((rss_before + 16384))

jq -n \
  --argjson rss_before_kib "$rss_before" \
  --argjson rss_after_kib "$rss_after" \
  --argjson threads_before "$threads_before" \
  --argjson threads_after "$threads_after" \
  --argjson fd_before "$fd_before" \
  --argjson fd_after "$fd_after" \
  --argjson completed "$(printf '%s' "$status" | jq -r '.probe_completed_total')" \
  '{status:"passed", rss_before_kib:$rss_before_kib, rss_after_kib:$rss_after_kib, threads_before:$threads_before, threads_after:$threads_after, fd_before:$fd_before, fd_after:$fd_after, probe_completed_total:$completed}'
