#!/bin/sh

set -eu

STAGED=${STAGED:-/tmp/sing-box-adaptive-candidate}
TARGET=${TARGET:-/root/singbox/sing-box}
CONFIG=${CONFIG:-/root/singbox/config.json}
RUNTIME=${RUNTIME:-/run/singbox/config.runtime.json}
EXPECTED_SHA256=${EXPECTED_SHA256:?EXPECTED_SHA256 is required}
EXPECTED_VERSION=${EXPECTED_VERSION:?EXPECTED_VERSION is required}
API=${API:-http://127.0.0.1:9090}
PROXY=${PROXY:-http://127.0.0.1:8888}
STAMP=$(date +%Y%m%d-%H%M%S)
VERSION_STEM=$(printf '%s' "$EXPECTED_VERSION" | tr -c 'A-Za-z0-9._-' '_')
BACKUP=${BACKUP:-/root/codex-backups/${STAMP}-before-${VERSION_STEM}-low-disk}
ROLLBACK_BINARY=${ROLLBACK_BINARY:-/tmp/sing-box-before-${VERSION_STEM}-${STAMP}}
CHANGED=0

rollback() {
  code=$?
  trap - EXIT INT TERM
  if [ "$CHANGED" -eq 1 ]; then
    echo "rollout failed; restoring $ROLLBACK_BINARY" >&2
    rc-service singbox stop >/dev/null 2>&1 || true
    cp -f "$ROLLBACK_BINARY" "$TARGET"
    chmod 0755 "$TARGET"
    rc-service singbox start >/dev/null 2>&1 || true
  fi
  exit "$code"
}
trap rollback EXIT INT TERM

for command in awk cmp curl rc-service sha256sum ss; do
  command -v "$command" >/dev/null
done
test -x "$STAGED"
test -x "$TARGET"
test -s "$CONFIG"
test -s "$RUNTIME"
test "$(sha256sum "$STAGED" | awk '{print $1}')" = "$EXPECTED_SHA256"
"$STAGED" version | sed -n '1s/^sing-box version //p' | grep -Fx "$EXPECTED_VERSION"
"$STAGED" check -c "$CONFIG"
"$STAGED" check -c "$RUNTIME"

mkdir -p "$BACKUP"
cp -p "$TARGET" "$ROLLBACK_BINARY"
cp -a "$CONFIG" "$BACKUP/config.json"
cp -a "$RUNTIME" "$BACKUP/config.runtime.json"
cp -a /etc/init.d/singbox "$BACKUP/singbox.init"
sha256sum "$TARGET" "$ROLLBACK_BINARY" "$CONFIG" "$RUNTIME" > "$BACKUP/sha256-before.txt"
ip route > "$BACKUP/routes.before"
ss -lntH | awk '{print $4}' | sort -u > "$BACKUP/listeners.before"

CHANGED=1
rc-service singbox stop
cp -f "$STAGED" "$TARGET"
chmod 0755 "$TARGET"
rc-service singbox start

ready=0
for _ in $(seq 1 45); do
  if rc-service singbox status >/dev/null 2>&1 \
    && curl -fsS --max-time 3 "$API/version" > "$BACKUP/api-version-after.json" 2>/dev/null \
    && curl -fsS --max-time 6 "$API/proxies" > "$BACKUP/proxies-after.json" 2>/dev/null; then
    ready=1
    break
  fi
  sleep 1
done
test "$ready" -eq 1

test "$(sha256sum "$TARGET" | awk '{print $1}')" = "$EXPECTED_SHA256"
"$TARGET" version | sed -n '1s/^sing-box version //p' | grep -Fx "$EXPECTED_VERSION"
"$TARGET" check -c "$CONFIG"
"$TARGET" check -c "$RUNTIME"
cmp -s "$CONFIG" "$BACKUP/config.json"
cmp -s "$RUNTIME" "$BACKUP/config.runtime.json"
ip route > "$BACKUP/routes.after"
cmp -s "$BACKUP/routes.before" "$BACKUP/routes.after"
ss -lntH | awk '{print $4}' | sort -u > "$BACKUP/listeners.after"
cmp -s "$BACKUP/listeners.before" "$BACKUP/listeners.after"
test "$(curl -x "$PROXY" -fsS --max-time 30 -o /dev/null -w '%{http_code}' https://www.google.com/generate_204)" = 204

pid=$(pidof sing-box | awk '{print $1}')
test -n "$pid"
grep -E '^(VmRSS|RssAnon|Threads):' "/proc/$pid/status" > "$BACKUP/resources-after.txt"
ln -sfn "$BACKUP" /root/codex-backups/LATEST-ADAPTIVE-CANDIDATE

CHANGED=0
trap - EXIT INT TERM
printf 'rollout=passed\nbackup=%s\nrollback_binary=%s\npid=%s\n' "$BACKUP" "$ROLLBACK_BINARY" "$pid"
