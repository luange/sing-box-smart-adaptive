# Data plane v2: clean-room TC + AF_XDP

## Scope

This data plane is specified from observable sing-box behavior and Linux UAPI.
It does not reuse the implementation of the previous shared-network TC
classifier.  The old object remains a rollback oracle until v2 passes the
traffic matrix, then it is removed.

The Go process remains the control plane: configuration, routing, Smart health
profiles, outbound selection and accounting.  Packet admission is a bounded
data-plane responsibility.

## Front ends

Both front ends consume the same parsed packet description and policy action:

| Action | TC | XDP |
|---|---|---|
| direct | `TC_ACT_OK` | `XDP_PASS` |
| proxy TCP | `bpf_sk_assign` | `XDP_PASS` to TC |
| proxy UDP | socket-assign fallback | `bpf_redirect_map` to AF_XDP |
| unsupported/fragment | kernel/TC fallback | `XDP_PASS` |
| configured UDP/443 drop | `TC_ACT_SHOT` | `XDP_DROP` |

XDP must never redirect until the userspace XSK has published a ready queue.
If the queue or userspace engine disappears, the packet is passed to TC.

## Compatibility contract

- Existing inbound tags, route rules, PBR addresses and Smart groups do not
  change.
- TCP remains on TC socket assignment in the first production version.
- IPv4 and IPv6 are symmetric. Up to two VLAN headers are accepted.
- IPv4 fragments and IPv6 extension chains not safely parsed are passed to the
  kernel/TC fallback.
- Direct DNS prefixes are passed in kernel space. Other DNS follows sing-box.
- Flow verdict generation changes invalidate old decisions atomically.
- No URL, query, token or credential crosses the data-plane ABI.

## Bounded memory contract

Defaults for a one-queue router VM:

- UMEM: 4096 frames x 2048 bytes = 8 MiB.
- fill/RX/TX/completion rings: 2048 descriptors each.
- UDP flow table: 4096 fixed entries, 64 shards.
- ingress work queue: 2048 descriptors; overflow increments a counter and
  falls back instead of allocating.
- DNS and data UDP have separate counters and expiry policies.

No packet-path allocation is permitted after startup. Flow expiry returns the
frame and slot to their owning pools. RSS is a gate, not an advisory metric.

## Rollout gates

1. Parser corpus: IPv4/IPv6, two VLANs, TCP/UDP, truncation and fragments.
2. Verifier/load test for TC and XDP objects.
3. AF_XDP engine death must fall back without packet loss beyond in-flight
   frames.
4. 117 namespace/veth fault matrix.
5. 115 canary: five-region TCP plus DNS/UDP/QUIC, current RSS below 100 MiB.
6. Only after the canary is stable is the old TC source removed.

