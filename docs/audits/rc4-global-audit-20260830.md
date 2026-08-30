# RC4 global audit gate (2026-08-30)

This branch is based on official sing-box `v1.14.0-rc.4`. The global gate
keeps the four moving parts separate:

- Smart/Adaptive state and provider refreshes remain bounded, endpoint-scoped,
  and covered by Go race tests.
- eBPF v3 remains the production TC/socket-assign path; policy generations,
  DNS hints, and flow learning are tested without enabling AF_XDP.
- Smart Zig and the XDP Zig policy/adapter are built on Linux only, with
  x86_64 and aarch64 cross-builds and C ABI smoke checks.
- AF_XDP is an optional DIRECT-only accelerator. Proxy, DNS-conflict, unknown,
  malformed, fragmented, and established traffic stays on TC/kernel paths.

The new `rc4-global-audit.yml` workflow runs focused Smart/eBPF tests, race
tests, `go vet`, and Smart Zig Linux cross-builds. It does not compile on
macOS, mutate PVE, or deploy to 107/115.

The AF_XDP adapter uses one shared UMEM fill/completion ring and per-queue
RX/TX rings. A bounded frame ownership table prevents duplicate descriptors
across receive, transmit, completion, and recycle paths. The XDP control map
is enabled only after mode-specific attach, every XSK queue binding, and
generation/bank agreement. Any failed probe, link/queue change, or ring
backpressure returns to TC.

Remaining acceptance is environmental, not an unguarded code path: a separate
multi-queue physical/virtio lab must demonstrate native/copy/offload attach,
bidirectional DIRECT forwarding, no fill starvation, link-change rollback,
and no proxy p95 regression before any production host is eligible. VM115 is
currently TC-only because its device probe reports no XDP program capability;
its two virtio queues alone are not sufficient.
