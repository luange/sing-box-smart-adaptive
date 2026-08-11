# eBPF shared-network flow lifecycle

## Problem

The shared socket-assignment data plane used one destructive original-
destination lookup for both TCP and UDP. That lifecycle is valid for an
accepted TCP connection, but invalid for UDP: DNS, QUIC, voice and games can
deliver many datagrams with the same five-tuple through one shared listener.
The first datagram consumed the map entry and later datagrams were rejected
before routing. Browser TCP fallback made the failure intermittent.

An independent long-running failure existed in the direct-flow verdict map:
timestamps made entries logically expired, but a plain hash retained their
slots. Eventually the map could reject new verdicts despite containing only
expired epochs.

## Unified model

| State | Owner | Read semantics | Reclamation |
|---|---|---|---|
| TCP original destination | kernel until `accept` | `TakeOriginal`, exactly once | delete on successful take |
| UDP original destination | kernel flow cache | `LookupOriginal`, repeatable | bounded LRU; every active datagram refreshes recency |
| Direct-flow verdict | kernel flow cache | repeatable while unexpired | bounded LRU plus timestamp validation |
| UDP userspace session | `udpnat2` | one session per tuple | idle timeout/capacity eviction |
| Smart health/profile | shared control plane | many groups consume one profile | process lifetime only |

The maps are bounded at compile time. No URL, query string, token or credential
is stored in the flow keys or diagnostics.

## Required validation

1. Linux generate/check and tagged test/race/vet.
2. TCP original tuple is unavailable after `TakeOriginal`.
3. UDP original tuple remains identical across multiple lookups.
4. Concurrent multi-datagram UDP and QUIC do not increment
   `OriginalDstLost`.
5. TCP, DNS UDP and data UDP are tested independently.
6. Long-running churn cannot exhaust redirect or verdict maps.
7. Production promotion requires successful YouTube page/video/seek/load-more,
   Google 204, normal TCP and resource gates on the isolated VM first.

## Router and Landscape comparison

Read-only inspection of the Panabit gateway showed that its forwarding plane
does not create one normal Linux socket or conntrack entry for every forwarded
UDP flow. The observed kernel conntrack table and UDP socket count stayed near
zero under traffic; proprietary UIO/KNI packet workers own the fast path.

Landscape uses the same architectural boundary in an open implementation:

- XDP/TC owns direct forwarding and NAT in bounded kernel maps.
- BPF timers reclaim NAT state with protocol-specific lifetimes.
- DNS policy remains in userspace, while `SO_REUSEPORT` dispatch selects a
  long-lived socket by policy flow and protocol instead of creating one socket
  per query.
- ring buffers carry metrics/events, never packet payloads.

These are design references, not copied code. A proxy cannot move encrypted
Trojan/Hysteria/etc. UDP into a pure kernel NAT path. Our applicable split is:

1. explicit direct TCP/UDP: kernel verdict fast path;
2. proxied UDP: bounded `udpnat2` session and queue state;
3. DNS: multiplex by policy/upstream lane;
4. transactional UDP: feed request/response outcome to the node profile;
5. control-plane events: bounded metadata only.

## Real UDP health consumption

Both AdaptivePool and ordinary `type: smart` must consume real transactional
UDP evidence. A flow is a blackhole candidate only when it targets a known
request/response protocol (DNS, QUIC or STUN), transmitted at least one packet,
received no packet, and lived for at least one second. One-way UDP is ignored,
an idle timeout after any response is ignored, and one flow can submit at most
one failure.

VM117 validation of `tcv2.20` demonstrated that repeated HTTP/3-only timeouts
reduced the selected node reliability and moved subsequent traffic to the next
candidate, while ordinary YouTube TCP remained HTTP 200 and RSS stayed around
57--59 MiB. HTTP/3 support is still candidate-dependent; this feedback avoids
reusing a blackholed candidate but does not manufacture QUIC support where the
provider has none.
