#!/bin/sh

set -eu

ROOT=${ROOT:-/root/adaptive-test}
STAGED=${STAGED:-$ROOT/sing-box.new}
TARGET=${TARGET:-$ROOT/sing-box}
CONFIG=${CONFIG:-$ROOT/config.json}
ROLLBACK=${ROLLBACK:-$ROOT/sing-box.rollback}
LOG=${LOG:-$ROOT/process.log}

had_target=0
started_new=0

start_target() {
  setsid "$TARGET" run -c "$CONFIG" > "$LOG" 2>&1 < /dev/null &
}

rollback() {
  status=$?
  trap - EXIT INT TERM
  if [ "$started_new" -eq 1 ]; then
    new_pid=$(pgrep -f "^$TARGET run " | head -n 1 || true)
    if [ -n "$new_pid" ]; then
      kill "$new_pid" 2>/dev/null || true
    fi
  fi
  if [ "$had_target" -eq 1 ] && [ -x "$ROLLBACK" ]; then
    mv -f "$ROLLBACK" "$TARGET"
    chmod 0755 "$TARGET"
    start_target
  elif [ "$had_target" -eq 0 ]; then
    rm -f "$TARGET"
  fi
  exit "$status"
}

test -x "$STAGED"
"$STAGED" check -c "$CONFIG"

if [ -x "$TARGET" ]; then
  had_target=1
  cp -p "$TARGET" "$ROLLBACK"
fi

trap rollback EXIT INT TERM

old_pid=$(pgrep -f "^$TARGET run " | head -n 1 || true)
if [ -n "$old_pid" ]; then
  kill "$old_pid"
  deadline=$(($(date +%s) + 10))
  while kill -0 "$old_pid" 2>/dev/null; do
    if [ "$(date +%s)" -ge "$deadline" ]; then
      kill -KILL "$old_pid"
      break
    fi
    sleep 1
  done
fi

mv -f "$STAGED" "$TARGET"
chmod 0755 "$TARGET"
start_target
started_new=1

deadline=$(($(date +%s) + 15))
while :; do
  if curl -fsS -H 'Authorization: Bearer adaptive-test-only' http://127.0.0.1:19091/adaptive-pools/v1/ > /dev/null 2>&1; then
    break
  fi
  if [ "$(date +%s)" -ge "$deadline" ]; then
    tail -100 "$LOG" >&2
    exit 1
  fi
  sleep 1
done

new_pid=$(pgrep -f "^$TARGET run " | head -n 1)
rm -f "$ROLLBACK"
trap - EXIT INT TERM
printf '%s\n' "$new_pid"
