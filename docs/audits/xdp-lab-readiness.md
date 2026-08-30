# XDP lab readiness and PVE boundary

This audit records the hardware gate for the optional AF_XDP DIRECT
accelerator. TC v3 remains the production data plane until every gate below
has evidence from an isolated Linux lab.

## PCI passthrough is not a prerequisite

XDP generic/SKB and driver/native mode can run on a virtio-net interface. PCI
passthrough is only needed when a lab requires the guest to own a physical NIC
and its driver queues. It does not turn a single-queue virtio device into a
zero-copy AF_XDP device. Hardware/offload mode additionally requires a NIC
whose firmware accepts this program; virtio cannot provide that capability.

## Current production guests

The read-only PVE inspection on 2026-08-30 found the following for guests 107
and 115:

| Guest | Interface | Driver | RX/TX queues | vCPU | XDP decision |
|---|---|---|---:|---:|---|
| 115 | eth0, eth1 | virtio_net | 1 / 1 | 1 | keep TC; no AF_XDP |
| 107 | eth0, eth1 | virtio_net | 1 / 1 | not changed | keep TC; no AF_XDP |

The PVE definition for 115 has `net0`/`net1` as virtio devices and no
`queues=` setting. No PCI device is passed through. Changing this on a live
gateway would be a maintenance operation and is not part of XDP enablement.

## Admission and rollback

At startup, `mode=auto` probes offload, native, then generic/SKB in that order.
Each candidate must pass the real verifier/attach path and an AF_XDP bind for
every selected queue. A missing feature, queue count below two, bind failure,
link/MTU change, or ring starvation leaves `xdp.enabled` false and keeps TC
active. Explicit modes fail closed to TC; they never silently downgrade.

An approved lab must provide at least two queues and two vCPUs, then record:

1. feature query and mode-specific attach result;
2. zero-copy (or explicitly allowed copy) XSK bind for every queue;
3. DIRECT ingress and paired-interface outbound forwarding;
4. proxy/unseen PASS to TC, queue/MTU change detach, and starvation fail-open;
5. 64/128-byte PPS, p95 latency, RSS, and 24-hour soak versus TC.

Until those artifacts exist, XDP is an opt-in lab accelerator and must not be
enabled on guests 107 or 115.
