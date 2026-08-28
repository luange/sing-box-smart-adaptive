# Smart Engine architecture

## Decision

Smart is split into a host-neutral policy kernel and a host adapter. The
kernel is the Zig library in `smart-engine/`; the adapter remains responsible
for sing-box or mihomo integration. The kernel never opens sockets, resolves
DNS, reads providers, persists state, emits logs, or owns API objects.

The boundary is a versioned C ABI. Hosts provide a bounded candidate snapshot
(`id`, health evidence, latency, jitter, throughput, weight and eligibility)
and report observations. The kernel returns a decision plus a reason. This
keeps provider refreshes and core-specific object lifetimes outside the policy
code, so a future mihomo adapter can reuse the same binary and tests.

The ABI has an additive profile entry point for interactive, bulk and UDP
traffic. The original `smart_engine_choose` remains interactive for older
hosts; unknown profile values fall back to interactive scoring.

## Modules

- `model.zig`: ABI-safe data types and state constants.
- `metrics.zig`: fixed-capacity, allocation-free observation table. Entries are
  evicted by oldest update when the limit is reached; an open-addressing index
  makes normal lookup expected O(1), and reset releases no hidden map capacity.
- `scoring.zig`: pure reliability/latency/jitter/weight scoring functions.
- `policy.zig`: incumbent retention, margin, confirmation and cooldown state
  transitions. It has no I/O and is deterministic for `(snapshot, now)`.
- `lib.zig`: thin lifecycle and C ABI facade.

Confirmation and cooldown timestamps cross the ABI as process-relative
monotonic milliseconds. The Go adapters convert their `time.Time` input from
one process origin, so an NTP step cannot trigger an early switch or extend a
cooldown unexpectedly. If a provider refresh removes the incumbent, the
kernel immediately adopts the best eligible candidate; it never returns an
ID that is absent from the current snapshot while waiting for confirmation.

The Go implementation remains the zero-dependency reference backend. Linux
release builds select the in-process Zig adapter with the `smart_zig` build
tag after the same conformance gate; provider, routing, and API code are
unchanged.

The Go adapters send candidates through the existing batch ABI entry point and
reuse one conversion buffer per lock shard. Smart bounds each shard to four
contexts; AdaptivePool bounds each shard to eight (128 total). Different
service contexts can rank concurrently without retaining a large candidate
buffer per context.

## Passive bulk throughput gate

Bulk candidates can be bypassed after the configured number of real-traffic
throughput observations falls below `passive_throughput_floor_bps` (default
512 KiB/s, two observations). This gate never fetches a probe resource and
never interrupts an existing stream. It marks the candidate hard-open for the
next new connection; the normal bounded candidate list then provides the
failover opportunity. Service-local throughput takes precedence over global
history, so a slow YouTube path cannot be hidden by unrelated traffic.

## Invariants and evolution

Candidate IDs are stable endpoint identities, not provider display names.
Only eligible, non-open candidates can be selected. A current candidate is
retained unless the relative improvement exceeds `switch_margin`, the new
candidate is observed for the configured confirmation count and time, and the
cooldown has elapsed. Arithmetic is clamped and timestamp addition saturates.

New evidence fields must be appended to the ABI or introduced with an ABI
version; existing field order and enum values are never reused. Any host
integration must add deterministic parity tests before production enablement.

## Alternatives rejected

- A full Zig proxy rewrite would duplicate sing-box protocol, DNS, TLS and
  platform code, creating a large compatibility surface and a long migration
  period. It is not justified by Smart's policy workload.
- A subprocess policy daemon would be portable but adds IPC latency, failure
  recovery and another long-lived process to operate. The in-process library
  keeps one bounded state owner.
- Zig eBPF bindings are not a prerequisite here. The data plane and its kernel
  ABI remain separate; Smart receives evidence only. This avoids coupling a
  policy release to kernel/BTF support.

## Rollout gates

1. Linux CI builds and tests the Zig library, links a C ABI smoke harness, and
   cross-builds amd64 and arm64 libraries.
2. A Go reference adapter feeds identical snapshots and compares every
   decision/reason transition, including empty and over-limit inputs.
3. A canary host enables the release binary's `smart_zig` backend and records
   switch audits, RSS and latency for at least 72 hours.
4. ABI mismatch or allocation failure falls back to Go with an explicit log;
   provider refresh, DNS and routing behavior remain unchanged.
