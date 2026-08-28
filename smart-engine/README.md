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

The optional `conformance/` package is built by Linux CI with the `smart_zig`
tag. It links the produced library through the C ABI and compares the
transition sequence with a Go reference. Production release jobs compile the
same library for each Linux architecture/libc pair before building sing-box.

The host owns node discovery, EndpointProfile/health evidence, dialing,
persistence, logging, and API compatibility. This prevents the policy engine
from opening sockets or reimplementing Provider logic. The default developer
build keeps the reference Go policy for zero-dependency development.

Build and test with Zig 0.14+:

```sh
zig build test
zig build -Doptimize=ReleaseFast
```

Linux release builds select Zig with `smart_zig` and link the matching static
library. ABI mismatch or allocation failure safely falls back to the reference
Go policy and emits a warning; manual pins, EndpointProfile, failure wakeups,
and switch auditing remain host-owned in either mode.
