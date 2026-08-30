# Next-gen XDP policy core

Host-neutral Zig module for the optional AF_XDP DIRECT fast path.  The Linux
host adapter is now implemented in `src/linux_adapter.zig` and exported as a
small C ABI in `include/xdp_engine.h`; non-Linux builds select an explicit
unsupported-platform stub.

Design: `docs/design/next-gen-xdp.md`.

This directory classifies packets, evaluates NIC capability samples, selects
hardware/native/generic XDP mode only after a real program probe, and tracks
attach/fallback state. `afxdp.zig` owns bounded ring arithmetic;
`linux_adapter.zig` owns Linux AF_XDP socket/UMEM/ring/poll/ownership
operations. Proxy traffic is never mapped to `XDP_REDIRECT`.

The adapter does not attach or enable the XDP policy by itself. A host must
first verify the program/mode, open and bind every queue, publish every XSK
FD to the XSKMAP, and only then enable the separate XDP control record. Any
failure keeps TC as the live path. The sing-box option therefore remains
gated until a host integration supplies those ordering guarantees.

Mode selection is conservative:

- `auto`: verified hardware offload → verified native/zero-copy → verified
  generic/SKB; otherwise TC.
- `skb`, `native`, `offload`: explicit mode, no silent downgrade.
- Every empty XSK slot, ring-starvation event, verifier failure, link change,
  or queue mismatch returns traffic to TC/kernel forwarding.

The kernel object is `common/ebpf/v3/kern/xdp.bpf.c`; its mode-aware loader is
the Linux-only `common/ebpf/native/xdp_runtime.c`. There is no userspace TCP/
UDP stack: "outbound" means a DIRECT frame is transmitted by the adapter's
paired TX ring after it has been classified by the ingress program. Proxy and
uncertain traffic stay in the kernel/TC path.

The host must serialize `Session` methods. The core holds no locks and no
global mutable session.

## Build (Linux CI / PVE only)

Do not compile on macOS. Do not deploy to hosts 107 or 115.

```sh
zig build test -Dcpu=baseline
zig build -Dcpu=baseline -Doptimize=ReleaseFast
# Linux-only cross builds (run in CI, not on macOS)
zig build -Dtarget=x86_64-linux-gnu -Dcpu=baseline -Doptimize=ReleaseFast
zig build -Dtarget=aarch64-linux-gnu -Dcpu=baseline -Doptimize=ReleaseFast
```

Zig 0.14, portable `baseline` CPU, same convention as `smart-engine/`.
