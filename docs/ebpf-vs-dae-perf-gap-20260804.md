# eBPF vs dae 性能差距（2026-08-04 / rc49 closeout）

## 产品前提

- **Linux-only**；DNS prefill **不做**（保 DNS 灵活性）。
- 出站加速仅 `outbound_offload`（无独立 `type: ebpf` out）。
- Lab：112 `10.30.0.219` → PVE `10.20.20.3` / `fd00:30::3` / `240e:ff:30::3`。
- 二进制：`1.14.0-beta.4-reF1nd-luan-adaptive.rc49-dae-maturity`。

## dae 公开基准（官方表 2023-02，网关拓扑）

| 路径 | dae | sing-box tproxy | sing-box TUN |
|---|---|---|---|
| Direct | **4.33 Gbit/s** | ~0.5–0.8 G | ~0.13–0.26 G |
| SS aes-256-gcm | ~0.47–0.66 G | ~0.42–0.63 G | 更低 |

红利在 **Direct 不进用户态**；代理路径与 tproxy 同级。绝对值不可与本 lab 跨机对比。

## Phase 0 同机矩阵（112，2026-08-03 lab-closeout）

iperf3 10s；CPU ≈ sing-box `utime+stime` jiffies / 墙钟（HZ~100）。

| ID | 配置 | 目标 | 吞吐 (receiver) | sing-box CPU≈ |
|---|---|---|---|---|
| **L0** | sing-box **stopped**（裸机） | v4 `10.20.20.3:5202` | **15684 Mbit/s** | 0 |
| **L0** | stopped | v6 `fd00:30::3:5201` | **15810 Mbit/s** | 0 |
| **L3** | splice ON (`half_close=close`) | v4 `:5202` | 3965 Mbit/s† | 26% |
| **L3** | splice ON | v6 `fd00:30::3:5201` | **15765 Mbit/s** | **10%** |
| **L4** | splice kill-switch (`passthrough`=用户态 copy) | v4 `:5202` | 13273 Mbit/s | **56%** |
| **L1** | private DIRECT + copy | v4 `:5202` | 13250 Mbit/s | 57% |
| **L2** | verdict learn 后 | v4 `:5202` | iperf 控制通路曾 broken pipe；HTTP learn 见下 | learn 后 CPU 采样 ~2% |

† L3 v4 本轮异常偏低（同窗有其它负载/5202 争用可能）；**以 L3 v6 ≈ L0 与 L4 CPU 对照为准**。历史基线（rc44c）splice ON 曾测 **15.5 Gbit/s @14% CPU**（`docs/ebpf-splice-benchmark-20260803.md`）。

### 解读

| 对比 | 结论 |
|---|---|
| L3 v6 vs L0 | **≈ line-rate**（15765 vs 15810），splice 数据面接近裸机 |
| L4 copy vs L3 | copy CPU **~56%** vs splice **~10–26%**；splice 省 CPU 明确 |
| L0/L1 私网 | 未下沉时仍进用户态中继（L1 copy），**不是** dae 式 L3 旁路；需 verdict/bypass |
| 与 dae 表 | 代理/splice 路径已强；**DIRECT 内核 hit** 才是 dae 同档（见 W1） |

## Verdict / W1 F-5（rc49）

### v4（私网 `10.20.20.3:18080`，Q3 后无需 `allow_with_sniff`）

```
learn wrote DIRECT: 10.20.20.3:18080
verdict metrics: writes=1, skips=0, kernel_hits=49, expired=0, gen_mismatch=0
HTTP 50/50
```

### v6（非本机前缀 `240e:ff:30::3:18080` + 临时 `ip_cidr→DIRECT`）

> 注意：`fd00:30::3` / 同 /64 ULA 在 112 上落入 **local interface bypass**（`bypass_cidr ipv6:7`），**不会进用户态**，故无法 learn——这是预期旁路，不是 v6 verdict bug。

```
learn wrote DIRECT: [240e:ff:30::3]:18080 ttl=45s
verdict metrics: writes=1, skips=0, kernel_hits=150, expired=0, gen_mismatch=0
HTTP v6 200/200；TTL 后再次 learn wrote（条目过期后回用户态再学）
HTTP v4 回归 30/30
```

| F-5 判据 | v4 | v6 |
|---|---|---|
| `kernel_hits>0` 且增长 | ✅ 49 | ✅ 150 |
| 应用层 n/n | ✅ | ✅ 200/200 |
| `gen_mismatch` 未风暴 | ✅ 0 | ✅ 0 |
| TTL 后可再学 | ✅（既有） | ✅ 再次 `learn wrote` |
| 测完 `verdict=off` | ✅ | ✅ |

## `type: ebpf` out vs `outbound_offload`

**无性能差**。独立 out type 不更快。合同禁止。

## 明确不做

- DNS prefill（保 DNS 灵活性）
- 全量 TC 规则引擎
- C.3 UDP offload（冻结）
