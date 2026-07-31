#!/bin/sh

set -eu

STAGED_CONFIG=${STAGED_CONFIG:-/tmp/config.adaptive-shadow.json}
TARGET_CONFIG=${TARGET_CONFIG:-/root/singbox/config.json}
RUNTIME_CONFIG=${RUNTIME_CONFIG:-/run/singbox/config.runtime.json}
BINARY=${BINARY:-/root/singbox/sing-box}
API=${API:-http://127.0.0.1:9090}
PROXY=${PROXY:-http://127.0.0.1:8888}
ERROR_LOG=${ERROR_LOG:-/var/log/singbox/singbox.err}
STAMP=$(date +%Y%m%d-%H%M%S)
BACKUP=${BACKUP:-/root/codex-backups/${STAMP}-before-adaptive-shadow}
CHANGED=0
ERROR_OFFSET=0

rollback() {
  code=$?
  trap - EXIT INT TERM
  if [ "$CHANGED" -eq 1 ]; then
    rc-service singbox stop >/dev/null 2>&1 || true
    cp -f "$BACKUP/config.json" "$TARGET_CONFIG"
    rc-service singbox start >/dev/null 2>&1 || true
  fi
  exit "$code"
}
trap rollback EXIT INT TERM

for command in cmp curl jq rc-service sha256sum ss; do
  command -v "$command" >/dev/null
done
test -s "$STAGED_CONFIG"
test -s "$TARGET_CONFIG"
test -s "$RUNTIME_CONFIG"
test -x "$BINARY"

"$BINARY" check -c "$STAGED_CONFIG"
test "$(jq '[.outbounds[] | select(.type == "smart")]|length' "$STAGED_CONFIG")" -eq 5
test "$(jq '[.outbounds[] | select(.type == "adaptive_pool" and .shadow == true and (.tag | endswith("-ADAPTIVE-SHADOW")))]|length' "$STAGED_CONFIG")" -eq 5
test "$(jq '[.route.rules[]? | .outbound? // empty | select(endswith("-ADAPTIVE-SHADOW"))]|length' "$STAGED_CONFIG")" -eq 0
test "$(jq -S .route "$TARGET_CONFIG" | sha256sum | awk '{print $1}')" = "$(jq -S .route "$STAGED_CONFIG" | sha256sum | awk '{print $1}')"

mkdir -p "$BACKUP"
cp -a "$TARGET_CONFIG" "$BACKUP/config.json"
cp -a "$RUNTIME_CONFIG" "$BACKUP/config.runtime.json"
cp -a /etc/init.d/singbox "$BACKUP/singbox.init"
ip route > "$BACKUP/routes.before"
ss -lntH | awk '{print $4}' | sort -u > "$BACKUP/listeners.before"
if [ -f "$ERROR_LOG" ]; then ERROR_OFFSET=$(wc -c < "$ERROR_LOG"); fi

CHANGED=1
cp -f "$STAGED_CONFIG" "$TARGET_CONFIG"
rc-service singbox restart

ready=0
for _ in $(seq 1 60); do
  if rc-service singbox status >/dev/null 2>&1 \
    && curl -fsS --max-time 3 "$API/version" >/dev/null 2>&1 \
    && curl -fsS --max-time 6 "$API/adaptive-pools/v1/" > "$BACKUP/adaptive-status.json" 2>/dev/null \
    && test "$(jq '[.adaptive_pools | to_entries[] | select(.key | endswith("-ADAPTIVE-SHADOW")) | select(.value.shadow == true and .value.generation > 0 and .value.candidate_count > 0 and .value.candidate_count == .value.active_binding_count and .value.missed_observations == 0)]|length' "$BACKUP/adaptive-status.json")" -eq 5; then
    ready=1
    break
  fi
  sleep 1
done
test "$ready" -eq 1

"$BINARY" check -c "$TARGET_CONFIG"
"$BINARY" check -c "$RUNTIME_CONFIG"
ip route > "$BACKUP/routes.after"
cmp -s "$BACKUP/routes.before" "$BACKUP/routes.after"
ss -lntH | awk '{print $4}' | sort -u > "$BACKUP/listeners.after"
cmp -s "$BACKUP/listeners.before" "$BACKUP/listeners.after"
test "$(curl -x "$PROXY" -fsS --max-time 30 -o /dev/null -w '%{http_code}' https://www.google.com/generate_204)" = 204

if [ -f "$ERROR_LOG" ] && tail -c "+$((ERROR_OFFSET + 1))" "$ERROR_LOG" 2>/dev/null \
  | grep -Ei 'panic|fatal' \
  | grep -Fiv 'sing-box did not close!' \
  | grep -q .; then
  exit 1
fi

ln -sfn "$BACKUP" /root/codex-backups/LATEST-ADAPTIVE-SHADOW
CHANGED=0
trap - EXIT INT TERM
printf 'shadow_rollout=passed\nbackup=%s\n' "$BACKUP"
jq '{adaptive_pools: [.adaptive_pools | to_entries[] | select(.key | endswith("-ADAPTIVE-SHADOW")) | {tag:.key, generation:.value.generation, candidates:.value.candidate_count, bindings:.value.active_binding_count, missed:.value.missed_observations}]}' "$BACKUP/adaptive-status.json"
