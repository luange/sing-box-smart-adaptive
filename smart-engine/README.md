# Portable Smart policy engine

This directory contains the dependency-free Smart decision core written in Zig.
It has no sing-box, mihomo, Provider, socket, DNS, or platform dependencies.
The C ABI in `include/smart_engine.h` is the portability boundary for Go,
Rust, mihomo, or another host core.

The core owns only bounded metrics, score calculation, switch margin,
confirmation samples/time, cooldown, and deterministic state transitions. The
implementation is split into `model.zig`, `metrics.zig`, `scoring.zig`, and
`policy.zig`; `lib.zig` is only the C ABI facade. The observation store is an
inline fixed-capacity table, so reset cannot retain a large hash-map backing
allocation.

`smart_engine_choose_profile` exposes interactive, bulk and UDP weighting; the
original choose function remains an interactive-compatible entry point.

The optional `conformance/` package is only built by Linux CI with the
`smart_zig` tag. It links the produced library through the C ABI and compares
the transition sequence with a Go reference; it is not part of sing-box's
default build.

The host owns node discovery, EndpointProfile/health evidence, dialing,
persistence, logging, and API compatibility. This prevents the policy engine
from opening sockets or reimplementing Provider logic.

Build and test with Zig 0.14+:

```sh
zig build test
zig build -Doptimize=ReleaseFast
```

Production remains on the Go backend. A Go adapter and `smart_zig` build tag
are intentionally not enabled yet: first run the Linux CI job, then add a
reference-vs-Zig conformance suite for score, margin, confirmation, cooldown,
and failure recovery. Only after that gate passes should the host select Zig
explicitly, with an immediate Go fallback for unsupported ABI versions.
