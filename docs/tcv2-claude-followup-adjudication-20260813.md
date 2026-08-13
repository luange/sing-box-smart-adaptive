# TC v2 Claude follow-up review adjudication (2026-08-13)

## Accepted and fixed

### P0: the committed embedded object was stale

Accepted.  `shared_network_v2.bpf.o` predated the BTF map conversion and was
therefore not equivalent to the reviewed source.  It has been regenerated on
Linux with Clang 19.1.7.  The committed object now contains `.maps`, `.BTF`,
and `.BTF.ext`.

CI now validates and executes the **committed** object before running any
generator.  This is deliberately ordered before `make generate`, so a green
generated object can no longer hide a stale object consumed by `go:embed` and
plain `go build`.

A byte-for-byte `git diff` gate was not adopted in the two-toolchain matrix:
Clang 18/19 and NDK Clang 21 legitimately emit different ELF/DWARF/BTF bytes.
Requiring one committed object to equal both products is not a valid
reproducibility test.  `make -C common/ebpf check` remains available when the
same compiler is used; CI instead applies section, kernel verifier, and real
socket-assignment data-path gates to the exact committed object.

### D-3: socket release and verifier evidence

Accepted as an evidence requirement, not as a source change.  The v2 data
path test sets `SING_BOX_EBPF_SHARED_DATA_PLANE=socket_assign`, loads
`sb_share_v2_in` into a real kernel, and exercises the socket assignment path.
The committed-object gate now runs that test before regeneration.  Removing
`bpf_sk_release` is rejected by the kernel verifier as an unreleased referenced
socket.

### Mark pollution runtime regression

Accepted.  The committed-object data-path test is now before generation and
therefore covers the actual embedded object.  Source-only inspection is not a
release gate.

## Review items not accepted as stated

### D-4: LRU eviction allegedly prevents reconstruction

Rejected.  The claim says an entry is evicted but a subsequent
`map_lookup(shared_redirect, key)` still finds that same entry.  Those states
cannot both be true.  On an LRU eviction the lookup misses; every UDP packet
still carries the original tuple, so `remember_original` reconstructs the
value before socket assignment.  The early return only suppresses writes while
the value actually exists.  This design avoids a map update on every QUIC/UDP
datagram without making an eviction permanent.

### InterruptSelective counter regression

Rejected after checking the consumer.  The log intentionally reports
`interrupted` (closed immediately) and `deferred` (scheduled after grace)
separately.  The cumulative `connectionsInterrupted` counter is updated by the
close callback for both immediate and deferred closes, so it represents actual
closures rather than scheduled closures.  Adding the two fields in the log
would double count their distinct semantics.

## Deferred, non-blocking suggestions

- `llvm-strip --strip-debug` was verified to retain `.maps`, `.BTF`, and
  `.BTF.ext` and reduces this object substantially.  It is not yet made part of
  generation because the repository supports system Clang and NDK Clang and
  needs one explicitly pinned strip tool before claiming reproducible output.
- AF_XDP probing remains a separate next-generation data-plane project.  It is
  not required to establish correctness of TC v2 and is not represented as
  completed here.

## Second follow-up

The review of the transparent UDP writer pool identified a valid shared-fate
issue.  A per-packet transient error previously removed and closed the socket
shared by all clients using the same source address.  This is fixed by keeping
the shared socket for transient and destination-specific failures (including
`ENOBUFS`) and invalidating it only when the descriptor itself is unusable
(`net.ErrClosed`, `EBADF`, or `ENOTSOCK`).  Tests cover both paths with two
references to the same entry.

The suggested `refs--` in the invalidation path was not used: the writer's
normal close callback would decrement the same reference again.  Classifying
descriptor-fatal errors avoids that double-release ambiguity while containing
transient failures to the packet that experienced them.

The DHCP bypass/mark regression is no longer skippable when port 67 cannot be
bound, and the system-Clang generation step now immediately runs
`make -C common/ebpf check` with that same toolchain.

### Provenance gate correction

The follow-up correctly observed that running `make check` immediately after
`make generate` only proves compiler determinism and does not compare the
committed v2 object with its source.  That placement has been removed.

The proposed direct pre-generation byte comparison was not adopted because
the committed object is produced by Clang 19.1.7 while the GitHub Ubuntu runner
uses Clang 18.1.3; their valid ELF, DWARF, and BTF encodings differ.  Instead,
generation now hashes the v2 source, map ABI, parser, BTF declarations, and
generation Makefile into an ELF `.sb.source` section.  CI recomputes and checks
that provenance hash on the committed object before any generation.  This
closes source/object drift without conflating it with cross-compiler byte
reproducibility, while the existing verifier and data-path gates still validate
the embedded bytes themselves.
