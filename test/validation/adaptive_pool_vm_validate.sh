#!/bin/sh

set -eu

ROOT=${ROOT:-/root/adaptive-test}
API=${API:-http://127.0.0.1:19091}
AUTH=${AUTH:-adaptive-test-only}
PROXY=${PROXY:-http://127.0.0.1:19080}
TARGET=${TARGET:-http://10.254.40.118:19080/health}
STATUS=$ROOT/status.json

pid=$(pgrep -f "^$ROOT/sing-box run " | head -n 1)
test -n "$pid"
kill -0 "$pid"

request() {
  curl -fsS -H "Authorization: Bearer $AUTH" "$@"
}

business_check() {
  response=$(curl -x "$PROXY" -fsS --max-time 5 "$TARGET")
  [ "$response" = ok ] || [ "$(printf '%s' "$response" | jq -r '.ok // false')" = true ]
}

deadline=$(($(date +%s) + 15))
while :; do
  request "$API/adaptive-pools/v1/ADAPTIVE-TEST/status" > "$STATUS"
  completed=$(jq -r '.probe_completed_total' "$STATUS")
  healthy=$(jq '[((.candidates // [])[]) | select(.state == "healthy")] | length' "$STATUS")
  if [ "$completed" -ge 2 ] && [ "$healthy" -eq 2 ]; then
    break
  fi
  if [ "$(date +%s)" -ge "$deadline" ]; then
    echo "adaptive pool did not become healthy" >&2
    exit 1
  fi
  sleep 1
done

test "$(jq -r '.candidate_count' "$STATUS")" -eq 2
test "$(jq -r '.generation' "$STATUS")" -eq 1
test "$(stat -c '%a' "$ROOT/state.key")" = 600
! grep -q "$AUTH" "$STATUS"

request -X PUT -H 'Content-Type: application/json' -d '{"name":"direct-b"}' "$API/proxies/ADAPTIVE-TEST"
request "$API/adaptive-pools/v1/ADAPTIVE-TEST/status" > "$STATUS"
test "$(jq -r '.pinned' "$STATUS")" = direct-b

request -X PUT -H 'Content-Type: application/json' -d '{"name":"\u267b\ufe0f \u667a\u80fd\u9009\u62e9"}' "$API/proxies/ADAPTIVE-TEST"
request "$API/adaptive-pools/v1/ADAPTIVE-TEST/status" > "$STATUS"
test "$(jq -r '.pinned // ""' "$STATUS")" = ""

before=$(jq -r '.probe_completed_total' "$STATUS")
request -X POST "$API/adaptive-pools/v1/ADAPTIVE-TEST/probes" > /dev/null
deadline=$(($(date +%s) + 10))
while :; do
  request "$API/adaptive-pools/v1/ADAPTIVE-TEST/status" > "$STATUS"
  after=$(jq -r '.probe_completed_total' "$STATUS")
  if [ "$after" -gt "$before" ]; then
    break
  fi
  if [ "$(date +%s)" -ge "$deadline" ]; then
    echo "manual probe did not complete" >&2
    exit 1
  fi
  sleep 1
done

business_check

rss_kib=$(awk '/^VmRSS:/ {print $2}' "/proc/$pid/status")
threads=$(awk '/^Threads:/ {print $2}' "/proc/$pid/status")
fd_count=$(find "/proc/$pid/fd" -mindepth 1 -maxdepth 1 | wc -l)

jq -n \
  --argjson pid "$pid" \
  --argjson completed "$after" \
  --argjson rss_kib "$rss_kib" \
  --argjson threads "$threads" \
  --argjson fd_count "$fd_count" \
  '{status:"passed", pid:$pid, probe_completed_total:$completed, rss_kib:$rss_kib, threads:$threads, fd_count:$fd_count}'
