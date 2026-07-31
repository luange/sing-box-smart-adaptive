#!/bin/sh

set -eu

ROOT=${ROOT:-/root/adaptive-test}
API=${API:-http://127.0.0.1:19091}
AUTH=${AUTH:-adaptive-test-only}
MODE=${1:?use fault or recover}
STATUS=$ROOT/fault-$MODE.json

request() {
  curl -fsS -H "Authorization: Bearer $AUTH" "$@"
}

case "$MODE" in
  fault)
	request "$API/adaptive-pools/v1/ADAPTIVE-TEST/status" > "$STATUS"
	before_accepted=$(jq -r '.probe_accepted_total' "$STATUS")
	before_coalesced=$(jq -r '.probe_coalesced_total' "$STATUS")
    for _ in $(seq 1 100); do
      request -X POST "$API/adaptive-pools/v1/ADAPTIVE-TEST/probes" > /dev/null
    done
    request "$API/adaptive-pools/v1/ADAPTIVE-TEST/status" > "$STATUS"
    test "$(jq -r '.probe_queue_depth' "$STATUS")" -le 2
    deadline=$(($(date +%s) + 15))
    while :; do
      request "$API/adaptive-pools/v1/ADAPTIVE-TEST/status" > "$STATUS"
      degraded=$(jq '[.candidates[] | select(.state == "degraded")] | length' "$STATUS")
      if [ "$degraded" -eq 2 ]; then
        break
      fi
      if [ "$(date +%s)" -ge "$deadline" ]; then
        echo "candidates did not record degraded probe failures" >&2
        exit 1
      fi
      sleep 1
    done
	after_accepted=$(jq -r '.probe_accepted_total' "$STATUS")
	after_coalesced=$(jq -r '.probe_coalesced_total' "$STATUS")
	test $(((after_accepted - before_accepted) + (after_coalesced - before_coalesced))) -ge 100
    test "$(jq '[.candidates[] | select((.reason // "") != "")] | length' "$STATUS")" -eq 2
    ;;
  recover)
    deadline=$(($(date +%s) + 15))
    while :; do
      request -X POST "$API/adaptive-pools/v1/ADAPTIVE-TEST/probes" > /dev/null
      sleep 1
      request "$API/adaptive-pools/v1/ADAPTIVE-TEST/status" > "$STATUS"
      healthy=$(jq '[.candidates[] | select(.state == "healthy")] | length' "$STATUS")
      if [ "$healthy" -eq 2 ]; then
        break
      fi
      if [ "$(date +%s)" -ge "$deadline" ]; then
        echo "candidates did not recover" >&2
        exit 1
      fi
    done
    ;;
  *)
    echo "unknown mode: $MODE" >&2
    exit 2
    ;;
esac

jq '{mode: $mode, candidate_count, probe_queue_depth, probe_deferred_total, probe_completed_total, state_entries, candidates: [.candidates[] | {tag, state, reason}]}' --arg mode "$MODE" "$STATUS"
