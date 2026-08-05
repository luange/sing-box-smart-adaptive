# eBPF lab VM112 — config migrated from 116

## Policy
- **116**: production-ish Alpine gateway — do not break for splice experiments.
- **112**: Debian lab receives 116 config clone for eBPF in/out testing.

## Access
| | |
|---|---|
| vmid | 112 `ebpf-splice-lab` |
| IP | 10.30.0.219 (vmbr100) |
| SSH | `ssh adaptive-vm112` / `root@10.30.0.219` |
| binary | `/root/singbox/sing-box` rc42-ebpf-inout |
| config | `/root/singbox/config.json` |
| service | `systemctl status sing-box` |

## What was migrated
- Full `config.json` from 116 (inbounds/outbounds/providers/route/dns/clash-api)
- `providers/airport.yaml`, `cache.db`, zashboard `ui/`
- Topology names `pa-hk/us/jp/sg/other` as **dummy** ifaces (+ addresses 10.116.20–24.1/24)
- systemd: `sing-box.service` + `pa-ebpf-ifaces.service`

## Lab adaptations (vs 116)
1. `capture_local: true` — test eBPF cgroup path on the box itself  
2. `shared_network.include_interface`: pa-* only (not eth0, keep SSH/mgmt clean)  
3. `data_plane: socket_assign` + same mark/table as 116  
4. `outbound_offload.splice.enabled: true` (eBPF out)  
5. blanket `PA-in reject` → `PA-in → select` so local capture is not blackholed  
6. Kernel: Debian cloud **CONFIG_BPF_STREAM_PARSER=y**

## Verified
| Check | Result |
|---|---|
| service active | yes |
| eBPF inbound attach | yes (cgroup + TC on pa-*) |
| eBPF outbound splice attach | **yes** (`eBPF outbound splice attached`) |
| SOCKS mixed-in :8888 → Google | **204** (works; occasional TLS flake under healthcheck storm) |
| clash-api :9090 | version ok, ~355 proxies |
| DIRECT public 1.1.1.1 via capture | may timeout (path/protect/loop investigation) |

## W2 IPv6 splice lab notes (rc46)

**EACCES root cause (historical):** 16-byte `memcpy` from `skb->local_ip6`/`remote_ip6`
and mixing ip4+ip6 fields without family-isolated branches. Fix: `fill_splice_key`
with `if (family == AF_INET)` / `else if (family == AF_INET6)` and four scalar
`__u32` loads for v6 (no 16B ctx memcpy, no ctx reads inside loops).

**Lab proof (112 → PVE):**
- Need IPv6 in `redirect_address` (e.g. `fd53:696e:672d:626f::/64`) so `connect6` attaches.
- Destination must **not** fall inside `localInterfacePrefixes` bypass (do not put the
  same /64 on eth0 as the destination; use a /128 source on another prefix + on-link route).
- Route lab CIDR to `DIRECT`; `pair active` on pure v6 HTTP; iperf3 **~16.4 Gbits/s** v6.
- `make -C common/ebpf check`: `splice.bpf.o` 2536B matches `.c`.

## Test commands
```bash
ssh adaptive-vm112
systemctl status sing-box
journalctl -u sing-box -f | grep -E 'splice|eBPF'
curl -x socks5h://127.0.0.1:8888 -I https://www.google.com/generate_204
curl -s http://127.0.0.1:9090/version
```
