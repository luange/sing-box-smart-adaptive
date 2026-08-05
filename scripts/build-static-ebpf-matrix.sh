#!/usr/bin/env bash
# Build sing-box with_ebpf static-ish matrix:
#   linux/{amd64,arm64} x {glibc,musl}
# Requires: docker (colima ok), source tree with modules.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="${VERSION:-1.14.0-beta.4-reF1nd-luan-adaptive.rc49}"
OUT="${OUT:-$HOME/Desktop/sing-box-adaptive-${VERSION}-static}"
TAGS_BASE="$(tr -d ' \n' <"$ROOT/release/DEFAULT_BUILD_TAGS_OTHERS")"
TAGS="${TAGS_BASE},with_ebpf"
LDFLAGS_SHARED="$(tr -d '\n' <"$ROOT/release/LDFLAGS" 2>/dev/null || true)"
GOPROXY="${GOPROXY:-https://proxy.golang.org,direct}"
GOTOOLCHAIN="${GOTOOLCHAIN:-local}"

mkdir -p "$OUT"
echo "ROOT=$ROOT"
echo "OUT=$OUT"
echo "VERSION=$VERSION"
echo "TAGS=$TAGS"

# ---------- 1) generate bpfel objects (arch-independent) ----------
echo "==> generate eBPF objects"
docker run --rm --platform linux/arm64 \
  -v "$ROOT:/src" -w /src/common/ebpf \
  debian:bookworm-slim bash -c '
    set -euo pipefail
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq clang llvm make ca-certificates linux-libc-dev >/dev/null
    make generate
    ls -la native/*.bpf.o
  '

build_one() {
  local platform="$1" # linux/amd64 | linux/arm64
  local libc="$2"     # glibc | musl
  local goarch goos=linux
  case "$platform" in
    */amd64) goarch=amd64 ;;
    */arm64) goarch=arm64 ;;
    *) echo "bad platform $platform"; return 1 ;;
  esac

  local dest="$OUT/linux-${goarch}-${libc}"
  mkdir -p "$dest"
  local image
  local setup
  local static_flags=""

  if [[ "$libc" == "musl" ]]; then
    # alpine + go from official tarball for exact 1.24.7 if needed
    image="golang:1.24-alpine"
    setup='
      apk add --no-cache build-base clang llvm linux-headers elfutils-dev libelf-static zlib-static bash git
    '
    static_flags='-linkmode external -extldflags "-static"'
  else
    image="golang:1.24-bookworm"
    setup='
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -qq
      apt-get install -y -qq build-essential clang llvm pkg-config libelf-dev zlib1g-dev linux-libc-dev bash git
      # try full static if available
      apt-get install -y -qq libc6-dev 2>/dev/null || true
    '
    # Prefer fully static when possible; fallback handled after build check
    static_flags='-linkmode external -extldflags "-static -s"'
  fi

  echo "==> build $platform $libc -> $dest"
  docker run --rm --platform "$platform" \
    -e GOPROXY="$GOPROXY" \
    -e GOTOOLCHAIN="$GOTOOLCHAIN" \
    -e CGO_ENABLED=1 \
    -e GOOS=linux \
    -e GOARCH="$goarch" \
    -v "$ROOT:/src" \
    -v "$dest:/out" \
    -w /src \
    "$image" bash -c "
      set -euo pipefail
      $setup
      go version
      uname -m
      # pre-download modules
      go mod download
      LDFLAGS=\"-X 'github.com/sagernet/sing-box/constant.Version=${VERSION}' ${LDFLAGS_SHARED} -s -w -buildid= ${static_flags}\"
      echo LDFLAGS=\$LDFLAGS
      if ! go build -trimpath -tags '${TAGS}' -ldflags \"\$LDFLAGS\" -o /out/sing-box ./cmd/sing-box; then
        echo 'static link failed, retry glibc dynamic with -static-libgcc' >&2
        if [[ '${libc}' == 'glibc' ]]; then
          LDFLAGS=\"-X 'github.com/sagernet/sing-box/constant.Version=${VERSION}' ${LDFLAGS_SHARED} -s -w -buildid= -linkmode external -extldflags '-static-libgcc'\"
          go build -trimpath -tags '${TAGS}' -ldflags \"\$LDFLAGS\" -o /out/sing-box ./cmd/sing-box
          echo dynamic-or-partial > /out/LINKSTYLE.txt
        else
          exit 1
        fi
      else
        if [[ '${libc}' == 'musl' ]]; then
          echo fully-static-musl > /out/LINKSTYLE.txt
        else
          echo static-glibc-attempt > /out/LINKSTYLE.txt
        fi
      fi
      chmod +x /out/sing-box
      file /out/sing-box | tee /out/file.txt
      ls -lh /out/sing-box
      # version only works on matching arch or with qemu user - try
      /out/sing-box version 2>/dev/null | tee /out/version.txt || true
      sha256sum /out/sing-box | tee /out/sing-box.sha256
    "
}

# native arm64 first (fast on colima), then amd64
build_one linux/arm64 musl
build_one linux/arm64 glibc
build_one linux/amd64 musl
build_one linux/amd64 glibc

# ---------- package ----------
{
  echo "# sing-box adaptive static matrix"
  echo
  echo "- Version: \`${VERSION}\`"
  echo "- Tags: \`${TAGS}\`"
  echo "- Source: \`$(cd "$ROOT" && git rev-parse --short HEAD 2>/dev/null || echo unknown)\`"
  echo "- Built: $(date -u +%Y-%m-%dT%H:%MZ)"
  echo
  echo "| artifact | size | link | sha256 |"
  echo "|----------|------|------|--------|"
  for d in "$OUT"/linux-*-*; do
    [[ -f "$d/sing-box" ]] || continue
    name=$(basename "$d")
    sz=$(ls -lh "$d/sing-box" | awk '{print $5}')
    link=$(cat "$d/LINKSTYLE.txt" 2>/dev/null || echo unknown)
    sum=$(awk '{print $1}' "$d/sing-box.sha256" 2>/dev/null || shasum -a 256 "$d/sing-box" | awk '{print $1}')
    echo "| \`${name}/sing-box\` | $sz | $link | \`$sum\` |"
  done
  echo
  echo "## file(1)"
  echo '```'
  for d in "$OUT"/linux-*-*; do
    [[ -f "$d/file.txt" ]] && echo "== $(basename "$d") ==" && cat "$d/file.txt"
  done
  echo '```'
  echo
  echo "## version (when runnable)"
  echo '```'
  for d in "$OUT"/linux-*-*; do
    [[ -f "$d/version.txt" ]] && echo "== $(basename "$d") ==" && cat "$d/version.txt"
  done
  echo '```'
} | tee "$OUT/BUILD-INFO.md"

(
  cd "$OUT"
  shasum -a 256 linux-*/sing-box > SHA256SUMS
)

echo "DONE -> $OUT"
ls -laR "$OUT"
