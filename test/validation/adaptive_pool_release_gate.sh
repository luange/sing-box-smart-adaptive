#!/bin/sh
set -eu
CSV=${1:?usage: $0 CSV [hours]}
REQUIRED_HOURS=${2:-72}
required_seconds=$((REQUIRED_HOURS * 3600))
[ -s "$CSV" ] || { echo "FAIL: empty CSV"; exit 1; }
awk -F, -v required="$required_seconds" '
NR == 1 { for (i = 1; i <= NF; i++) col[$i] = i; next }
{
  if (!start) start = $col["timestamp"]; end = $col["timestamp"]; samples++
  if ("missed_observations" in col && $(col["missed_observations"]) + 0 > 0) bad++
  if ("business_ok" in col && $(col["business_ok"]) + 0 == 0) business_bad++
  if ("rss_kib" in col) { rss = $(col["rss_kib"]) + 0; if (samples == 1) rss_first = rss; rss_last = rss }
  if ("fd_count" in col) { fd = $(col["fd_count"]) + 0; if (samples == 1) fd_first = fd; fd_last = fd }
}
END {
  if (!samples) { print "FAIL: no samples"; exit 1 }
  elapsed = end - start
  if (bad) { print "FAIL: missed observations present"; exit 2 }
  if (business_bad >= 3) { print "FAIL: three or more failed business samples"; exit 3 }
  if (rss_last - rss_first > 131072) { print "FAIL: RSS growth exceeds 128 MiB"; exit 4 }
  if (fd_last - fd_first > 32) { print "FAIL: FD growth exceeds 32"; exit 5 }
  if (elapsed < required) { printf "CONDITIONAL: elapsed=%ds required=%ds samples=%d\n", elapsed, required, samples; exit 10 }
  printf "PASS: elapsed=%ds samples=%d rss_delta=%d fd_delta=%d\n", elapsed, samples, rss_last-rss_first, fd_last-fd_first
}' "$CSV"
