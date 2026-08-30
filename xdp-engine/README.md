# Next-gen XDP policy core

Host-neutral Zig module for the optional AF_XDP DIRECT fast path.

Design: `docs/design/next-gen-xdp.md`.

This directory classifies packets, evaluates NIC capability samples, and
tracks attach/fallback state. It does not open sockets, bind AF_XDP, load BPF,
or talk to sing-box. Proxy traffic is never mapped to `XDP_REDIRECT`.

The host must serialize `Session` methods. The core holds no locks and no
global mutable session.

## Build (Linux CI / PVE only)

Do not compile on macOS. Do not deploy to hosts 107 or 115.

```sh
zig build test -Dcpu=baseline
zig build -Dcpu=baseline -Doptimize=ReleaseFast
```

Zig 0.14, portable `baseline` CPU, same convention as `smart-engine/`.
