# Next-gen XDP policy core

Host-neutral Zig module for the optional AF_XDP DIRECT fast path.

Design: `docs/design/next-gen-xdp.md`.

This directory classifies packets, evaluates NIC capability samples, selects
hardware/native/generic XDP mode only after a real program probe, and tracks
attach/fallback state. `afxdp.zig` owns bounded RX/TX/completion ring
ownership; a host adapter supplies Linux syscalls and the v3 map FDs. Proxy
traffic is never mapped to `XDP_REDIRECT`.

Mode selection is conservative:

- `auto`: verified hardware offload → verified native/zero-copy → verified
  generic/SKB; otherwise TC.
- `skb`, `native`, `offload`: explicit mode, no silent downgrade.
- Every empty XSK slot, ring-starvation event, verifier failure, link change,
  or queue mismatch returns traffic to TC/kernel forwarding.

The kernel object is `common/ebpf/v3/kern/xdp.bpf.c`; its loader is the
Linux-only `common/ebpf/native/xdp_runtime.c`. There is no XDP egress hook:
"outbound" means frames received on the opposite interface are classified by
the same ingress program and transmitted by the host's paired TX ring. A
userspace TCP/UDP stack is intentionally not part of this project.

The host must serialize `Session` methods. The core holds no locks and no
global mutable session.

## Build (Linux CI / PVE only)

Do not compile on macOS. Do not deploy to hosts 107 or 115.

```sh
zig build test -Dcpu=baseline
zig build -Dcpu=baseline -Doptimize=ReleaseFast
```

Zig 0.14, portable `baseline` CPU, same convention as `smart-engine/`.
