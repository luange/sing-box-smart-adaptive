# AF_XDP / TC 数据面 ABI 共用框架（2026-08-13）

## §0 结论

| # | 结论 |
|---|---|
| C-1 | **"ABI 共用"分四层，其中两层可以 100% 共用，两层完全不能。**混为一谈会做出一个既不是 TC 也不是 AF_XDP 的四不像。 |
| C-2 | 可共用的是 **map key/value 布局** 和 **包解析器**。解析器（`dataplane_v2_parser.h`）已经是正确形状——它吃 `(data, data_end)`，XDP 和 TC 都提供这两个指针。 |
| C-3 | 不可共用的是 **动作层** 和 **用户态运行时**。XDP **没有 `bpf_sk_assign`**，唯一可用动作是 `bpf_redirect_map()` 进 XSKMAP。 |
| C-4 | 真正的后果不是"包怎么到达"，而是 **AF_XDP 把内核 TCP 栈从路径上摘掉了**。拿到的是裸以太帧：没有 conntrack、没有 TCP、没有路由、没有 TPROXY。 |
| C-5 | **所以 AF_XDP 的 scope 必须限定为"直连 / bypass 的纯转发快路径"。**在这个 scope 下不需要终结 TCP，C-4 整条不成立，也不需要引入 gvisor。代理流量继续留在 TC → `sk_assign` → 内核 socket。 |
| C-6 | **收益在 PPS 和尾延迟，不在带宽。**直连现在走 `TC_ACT_OK` + 内核路由，全程在内核里已贴线速；把包捞到用户态再从 TX ring 打回去只会更慢。AF_XDP 真正赢的是小包场景（DNS 洪水、QUIC 小包、per-packet 开销主导）。**文档必须这么写**，否则用户开了它测带宽发现没变化，会认为是实现有问题。 |
| C-7 | 代理流量的天花板是用户态 AEAD，与包投递无关。**禁止宣称 AF_XDP 提升代理吞吐。** |
| C-8 | **硬件适配不需要认识任何硬件。**内核已把能力查询标准化（`IFLA_XDP_FEATURES`），且最终权威是 `bind()` 的返回值。四层探测见 §3.5，没有任何一层需要驱动表或允许列表。 |
| C-9 | 本项目自有部署（107/115）不满足前提：`pa-*` 是 macvlan、eth0 单队列（§2）。**这不影响上游把它作为可选后端交付**，只意味着作者无法在本地做性能验收，必须借多队列物理机。 |
| C-10 | **§1 那个分层重构独立于 AF_XDP 就值得做**——它是安全删掉死代码 v2、并把两份解析器收敛成一份的前提。这是本文档的最高优先交付。 |

---

## §1 ABI 分层：什么能共用，什么不能

本仓库里被叫做 "ABI" 的东西（`common/ebpf/outbound_abi.go` 注释：*"ABI mirrors of native/singbox_ebpf_out.h"*）其实只是第 1 层。完整分层：

### L1 — map key/value 布局：**100% 共用**

```go
type outVerdictKey struct { Family uint8; Protocol uint8; Port uint16; Addr [16]byte; Reserved uint32 }
```

AF_XDP 仍然用 BPF map。`sb_shared_flow_key` / `sb_shared_redirect_key` / `outVerdictKey` 不关心是哪个 hook 在读写。
**这一层原样复用，一行不改。** 现有的 `outbound_abi_test.go` size lock 机制继续有效。

### L2 — 包解析：**共用，且已经是对的形状**

`dataplane_v2_parser.h` 的签名是：

```c
static int sb_dp2_parse(void *data, void *data_end, struct sb_dp2_packet *packet)
```

它不接触 `__sk_buff`，只接触裸窗口。而：

| hook | 窗口来源 |
|---|---|
| `sched_cls` (TC) | `(void *)(long)skb->data`, `(void *)(long)skb->data_end` |
| `xdp` | `(void *)(long)ctx->data`, `(void *)(long)ctx->data_end` |

**所以解析器可以逐字节复用，不需要任何抽象层。**这是最大的一块可共用代码，而且已经在正确位置。

唯一要补的是 **多缓冲（multi-buffer）**：XDP 在 virtio_net 上开 GRO 时会拿到 `xdp_buff` 多帧链，`data_end` 只覆盖第一段。共用解析器必须在 XDP 侧先判 `bpf_xdp_get_buff_len()` 或直接对多帧 `XDP_PASS`。

### L3 — 动作层：**不可共用，硬边界**

| 能力 | TC `sched_cls` | XDP |
|---|---|---|
| 交给本机 socket | `bpf_sk_assign()` ✅ | **不存在** ❌ |
| 查已建立 socket | `bpf_skc_lookup_tcp()` ✅ | `bpf_sk_lookup_tcp()` ✅（但拿到也没用，无法 assign） |
| 重定向到用户态 | — | `bpf_redirect_map(&xsks, qid, 0)` → `XDP_REDIRECT` |
| 放行 / 丢弃 | `TC_ACT_OK` / `TC_ACT_SHOT` | `XDP_PASS` / `XDP_DROP` |
| 改 mark 影响 ip rule | `skb->mark` ✅ | **无 skb，不存在** ❌ |

这张表是 C-4 的全部依据：`sb_share_v2_in` 的整个后半段（`assign_established_socket` + listener `sk_assign` + `skb->mark`）在 XDP 里**一条都无法翻译**。

### L4 — 用户态运行时：**0% 共用**

| | TC 路径 | AF_XDP 路径 |
|---|---|---|
| 加载 | `object_loader.c` 手写 ELF 重定位 + attach `sched_cls` | 同样要加载一个 XDP 程序，**外加** 整套 socket 生命周期 |
| 数据通路 | 无——内核栈直接投递到 listener | UMEM 分配 + 4 个 ring（FILL / COMPLETION / RX / TX）+ `bind(netdev, queue_id)` + 轮询循环 + 帧归还 |
| TCP 终结 | 内核栈 | **必须自己实现**（见下） |

**L4 里最关键的一条**：AF_XDP 拿到的是裸帧，所以**这条路径能承载什么，完全由"要不要终结 TCP"决定**：

| scope | 是否需要用户态 TCP 栈 | 结论 |
|---|---|---|
| **直连 / bypass 纯转发**（本文档采纳） | **不需要** —— 只做 L2/L3 转发与策略判定，不看载荷 | ✅ 可做 |
| 代理流量（需解密重加密） | 必须终结 TCP → 只能接 gvisor netstack | ❌ 不做，见下 |

第二行为什么不做：sing-box 树里确实已有 gvisor netstack（`with_gvisor`，sing-tun 在用），架构上 `NIC → XDP → XSKMAP → AF_XDP socket → gvisor → 现有 proxy leaf` 是干净的。但它意味着**整条 inbound 路径重写**，且 gvisor 的单连接开销显著高于内核栈。对一个必须终结并重新加密的代理来说，用「内核栈效率」换「零拷贝 RX」是负收益——而且天花板本来就在 AEAD（C-7）。

**所以 AF_XDP 后端只挂直连快路径，代理流量一律留在 TC。**

---

## §2 作者自有部署不满足前提（不构成"不交付"的理由）

本节是**性能验收的约束**，不是功能取舍的依据。AF_XDP 后端照常交付，但作者无法在 107/115 上做 A/B，必须借多队列物理机（§6 门 9）。

### B-1 代理出口全是 macvlan → 无法挂 XDP

```
13: pa-us@eth0: ... macvlan mode bridge ... numtxqueues 1 numrxqueues 1
```

`pa-us` / `pa-jp` / `pa-sg` / `pa-other` 全部是 eth0 上的 macvlan。**macvlan 没有 `ndo_bpf`**——native XDP 挂不上，AF_XDP 更不可能（AF_XDP 必须 `bind()` 到一个真实的 (netdev, queue)）。

也就是说：**代理流量所在的接口从物理上就出不了 AF_XDP 这条路**。只有 LAN 侧 eth0 有可能。而 eth0 上的入向流量，现在 TC 已经在处理了。

### B-2 单队列 → AF_XDP 的性能模型直接失效

```
/sys/class/net/eth0/queues/ →  rx-0 tx-0
```

两台机的 eth0 都只有 1 个 RX / 1 个 TX 队列。AF_XDP 的全部性能优势来自 **每队列一个 socket、一个核、无锁、批量、零拷贝**。只有一个队列 = 只有一个核 = 没有任何横向扩展。

而现有 TC 路径是走内核栈的，softirq + Go 调度天然摊到所有核上。**单队列 AF_XDP 极可能比现状更慢。**

### B-3 virtio_net 零拷贝未经证实（次要）

内核版本没问题：107 是 `6.18.35-0-virt`，115 是 `6.12.100+deb13-cloud-amd64`，都 ≥ 6.11（virtio_net AF_XDP 零拷贝合入的版本）。

但 `ip -d link show eth0` **没有输出 xdp-features 行**，所以 ZC 是否真的 advertise 无法确认；virtio 的 ZC 还需要宿主 vhost 侧配合。拿不到 ZC 就退化成 copy mode，比 TC 更慢。

**这条要在动手前用 `bpftool net`/`xdp-loader status` 或一个最小 XDP 程序实测，不能假设。**

### B-4 它不打作者部署里现存的瓶颈

| 现存问题 | AF_XDP 是否有帮助 |
|---|---|
| udpnat 表满静默丢包 | 无。纯用户态逻辑缺陷 |
| per-session goroutine / 对象膨胀 | 无。会话模型不变 |
| 代理流量吞吐 | 无。天花板是用户态 AEAD/TLS |
| 直连**带宽** | 无。已经由 splice sockmap 贴住线速 |
| 直连**小包 PPS / 尾延迟** | **有。这是唯一的真实收益面（C-6）** |

---

## §3.5 硬件可用性探测：四层，零驱动知识

回答"总不成每个硬件都做驱动级兼容"——**不需要，一次都不需要。**内核已经把这件事标准化了，且最终权威是 `bind()` 的返回值。

### Tier 0 — 声明式查询（内核 ≥ 6.3，可选优化）

`RTM_GETLINK` 返回 `IFLA_XDP_FEATURES`，一个由**驱动自己填**的 u64 位图：

```
NETDEV_XDP_ACT_BASIC        (1<<0)   XDP_PASS/DROP/TX/ABORTED
NETDEV_XDP_ACT_REDIRECT     (1<<1)   bpf_redirect_map —— XSKMAP 必需
NETDEV_XDP_ACT_NDO_XMIT     (1<<2)
NETDEV_XDP_ACT_XSK_ZEROCOPY (1<<3)   ← AF_XDP 零拷贝，就是这一位
NETDEV_XDP_ACT_HW_OFFLOAD   (1<<4)
NETDEV_XDP_ACT_RX_SG        (1<<5)   多缓冲 RX
NETDEV_XDP_ACT_NDO_XMIT_SG  (1<<6)
```

- 准入条件：`REDIRECT | XSK_ZEROCOPY` 两位均置。
- `IFLA_XDP_ZC_MAX_SEGS` 给出 ZC 最大分段数。
- **`RX_SG` 置位 ⇒ 这张卡会给多帧链 ⇒ 解析器必须走多缓冲分支。**这把 §1 L2 那个待补项从"靠猜"变成运行时可判定。

**这一位图由驱动作者维护，不由本项目维护。这就是 C-8 的全部内容。**

附带推论：**macvlan / veth / wireguard 的黑名单是多余的**——它们没有 `ndo_bpf`，位图恒为 0，Tier 0 自然拒绝。（这也解释了为何 107/115 上 `ip -d link show eth0` 不打印 xdp-features 行。）

### Tier 1 — 内核当权威：直接 bind 一次（**强制**）

```
bind(xsk, &{ .sxdp_flags = XDP_ZEROCOPY })
    成功        → ZC 可用
    EOPNOTSUPP  → 退 XDP_COPY 重试
    仍失败      → 回落 TC
```

**Tier 1 不可省，Tier 0 只是优化。**两个理由：6.3 以前的内核没有那个位图；位图是驱动自报的，可能与实际能力不符。真正的判据永远是"bind 成功了吗"。Tier 0 的唯一价值是在浪费一整块 UMEM 分配之前先打出一条准确日志。

### Tier 2 — 队列拓扑

`ETHTOOL_GCHANNELS`，或数 `/sys/class/net/<if>/queues/rx-*`。队列数 < 2 直接判定无收益（B-2）。同样不需要认硬件。

### Tier 3 — 运行时看守（最容易漏）

静态探测覆盖不了的：`ethtool -L` 改队列数、MTU 变更、驱动 reset——**全都会让已有的 (netdev, queue) 绑定失效**。必须订阅 `RTM_NEWLINK`，检测到变更即重新探测或直接 detach 回落。

**AF_XDP 的绑定不是一次性事实，是需要持续维护的状态。**

### 探测结果矩阵

| 探测 | 层 | 失败动作 |
|---|---|---|
| P-1 | 0 | `REDIRECT` 未置 → 回落 TC + Info（含接口 kind，仅作诊断文案） |
| P-2 | 0 | `XSK_ZEROCOPY` 未置 → 回落 TC + Info |
| P-3 | 2 | RX 队列 < 2 → 回落 TC + Warn（单队列无横向扩展） |
| P-4 | 1 | `XDP_ZEROCOPY` bind 失败且 `XDP_COPY` 也失败 → 回落 TC + Warn |
| P-5 | 1 | `XDP_ZEROCOPY` 失败但 `XDP_COPY` 成功 → **默认仍回落 TC**，除非显式 `allow_copy_mode: true` |
| P-6 | 0 | `RX_SG` 置位 → 启用解析器多缓冲分支（非失败项，是配置项） |
| P-7 | 3 | 链路属性变更 → detach + 重新走 P-1..P-5 |

**全部失败动作都是回落，没有一项是报错退出。**

---

## §3 若仍要做：正确的分层框架

即使 §2 判定当前不落地，**下面这个分层是应该现在就做的**——因为它同时解决"两份解析器"和"v2 死代码"两个现存问题。

### 目标布局

```
common/ebpf/native/
  dataplane_abi.h          ← L1：map 布局 + 常量（Go 侧 outbound_abi.go 镜像）
  dataplane_parser.h       ← L2：sb_dp2_parse，纯 (data,end)，hook 无关   【已存在，改名收敛】
  dataplane_policy.h       ← L2.5：新增。纯策略判定，hook 无关
  hook_tc.bpf.c            ← L3：TC 动作层（sk_assign / mark / TC_ACT_*）
  hook_xdp.bpf.c           ← L3：XDP 动作层（redirect_map / XDP_*）  【可选，默认不编译】
```

### L2.5 是关键的新增层

把 `sb_share_v2_in` 里**所有不涉及动作的判定**抽成一个纯函数：

```c
enum sb_dp_decision {
    SB_DP_PASS,        /* 放行，不干预 */
    SB_DP_DROP,        /* 丢弃（如 drop_udp_443） */
    SB_DP_HANDOFF,     /* 需要交给用户态：TC→sk_assign，XDP→redirect */
};

static __attribute__((always_inline)) enum sb_dp_decision
sb_dp_classify(const struct sb_dp2_packet *packet,
               const struct sb_shared_control *control);
```

`destination_bypass()` / `learned_direct()` / 协议与 flag 门禁全部搬进去。这一层：

- **两个 hook 逐字节共用**
- 可以脱离内核单元测试（编译成普通 C，喂构造好的 `sb_dp2_packet`）
- 让动作层瘦到 20 行以内，`skb->mark` 那类污染 bug 无处藏身

### L3 的两个实现

```c
/* hook_tc.bpf.c */
SEC("classifier/ingress")
int sb_dp_tc_in(struct __sk_buff *skb) {
    /* ... parse, control lookup ... */
    switch (sb_dp_classify(&packet, control)) {
    case SB_DP_PASS:    return TC_ACT_OK;              /* mark 绝不设置 */
    case SB_DP_DROP:    return TC_ACT_SHOT;
    case SB_DP_HANDOFF: return tc_handoff(skb, &packet, control);  /* mark 只在这里设 */
    }
}
```

```c
/* hook_xdp.bpf.c —— 仅在 CONFIG 显式开启时编译 */
SEC("xdp")
int sb_dp_xdp_in(struct xdp_md *ctx) {
    /* ... 同一个 parser、同一个 classify ... */
    switch (sb_dp_classify(&packet, control)) {
    case SB_DP_PASS:    return XDP_PASS;
    case SB_DP_DROP:    return XDP_DROP;
    case SB_DP_HANDOFF: return bpf_redirect_map(&sb_xsks, ctx->rx_queue_index, XDP_PASS);
    }
}
```

注意 `bpf_redirect_map` 的第三参数用 `XDP_PASS` 作 flags——XSKMAP 槽位为空时回落到内核栈，而不是丢包。**这是 AF_XDP 侧的 fail-open 契约，必须这么写。**

### 能力探测门禁

见 **§3.5**。要点：探测分四层、零驱动知识、全部失败动作都是回落 TC 而非退出，且不得静默降级——每一项都要一条明确日志。

---

## §4 工作单

### X-1（P0，与 AF_XDP 无关，现在就做）解析器收敛 + L2.5 抽层

1. `dataplane_v2_parser.h` → `dataplane_parser.h`，补 XDP 多缓冲判定（`bpf_xdp_get_buff_len()` 或对多帧 PASS）。
2. 新增 `dataplane_policy.h`，把 `destination_bypass` / `learned_direct` / flag 门禁搬进 `sb_dp_classify()`。
3. `shared_network_v2.bpf.c` 重写为 `hook_tc.bpf.c`，动作层 ≤ 30 行。
4. **顺带修掉 `skb->mark` 污染**：mark 只在 `SB_DP_HANDOFF` 分支内设置。这是重构的免费收益。
5. 给 `sb_dp_classify` 写脱离内核的单测。

### X-2（P0）处置死代码 v2

`shared_network_v2.bpf.o` 被 `//go:embed` 进二进制，但**没有任何 Go 代码 load 或 attach 它**；生产实际跑的是 v1 `sb_share_in`（`bpftool prog show` → id 723）。

二选一，不允许维持现状：
- **(a) 删除**（建议）：删 `shared_network_v2.bpf.c` / `dataplane_v2*.h` / Makefile 条目 / embed 声明。X-1 的收敛工作改为直接作用于 v1 `shared_network.bpf.c`。
- **(b) 接上**：先修完 §5 的 D-1..D-4，再按 PROJECT.md 边界进 117/118 验证。

### X-3（P1）AF_XDP 后端 —— **可独立推进，但 scope 硬限定**

**scope：仅直连 / bypass 的纯转发快路径。不承载代理流量，不引入 gvisor（C-5）。**

1. `common/ebpf/xdp/probe.go`：§3.5 的 Tier 0/1/2/3 四层探测。**先做这个，它可以脱离数据面独立测试和验收。**
2. `common/ebpf/xdp/`：UMEM + 4 ring + `bind()` + 轮询循环 + 帧归还。
3. `hook_xdp.bpf.c`：复用 §3 的 L1/L2/L2.5，只写动作层。
4. 配置字段 `data_plane: "afxdp"`（与现有 `token` / `socket_assign` 并列），附 `allow_copy_mode`（默认 false）。
5. 文档措辞必须写明收益面是**小包 PPS 与尾延迟**，不是带宽（C-6）。

### X-4（P2）观测

`runtime_stats` 增加 `dataplane{backend, zerocopy, queues, rx_frames, tx_frames, fill_starved, comp_drops}`。`fill_starved` 是 AF_XDP 最常见的静默丢包源，必须暴露。

---

## §5 边界

| # | 禁止 | 原因 |
|---|---|---|
| D-1 | **禁止在 XDP 侧尝试 `bpf_sk_assign`** | 该 helper 在 XDP 程序类型下不存在，verifier 直接 reject |
| D-2 | **禁止在任何 PASS / DROP / fail-open 分支上残留 `skb->mark`** | 115 有 `from all fwmark 0x53420001 lookup 2026` → `local default dev lo`，带 mark 放行 = 直连流量被本地投递而断掉 |
| D-3 | **禁止对 SOCKMAP `map_lookup` 的返回值调 `bpf_sk_release`** | 该指针非 refcounted，`ref_obj_id == 0`；当前内核能过不代表可移植。保留则必须附 verifier log 证据 |
| D-4 | **禁止把不可重建状态放进 LRU** | `shared_redirect` 存原始目的地，被 LRU 挤掉即永久丢失，会话直接坏 |
| D-5 | **禁止 `bpf_redirect_map` 不带 `XDP_PASS` flag** | XSKMAP 槽空时必须回落内核栈，不得丢包 |
| D-6 | **禁止用驱动名 / 接口 kind 的硬编码列表作为准入门禁** | 能力必须来自 `IFLA_XDP_FEATURES` + `bind()` 返回值（§3.5）。kind 只允许出现在诊断日志文案里。维护驱动表 = 永远追不上上游 |
| D-7 | **禁止单队列下启用 AF_XDP** | 无横向扩展，实测会比 TC 慢；P-3 必须硬门禁 |
| D-8 | **禁止为 AF_XDP 引入用户态 TCP 栈** | scope 限定纯转发（C-5）；要终结 TCP 就说明 scope 越界了 |
| D-9 | **禁止宣称 AF_XDP 提升代理吞吐或直连带宽** | 代理天花板是 AEAD，直连带宽已由 splice 贴线速；收益只在小包 PPS（C-6、C-7） |
| D-10 | **禁止把 AF_XDP 绑定当成一次性事实** | `ethtool -L` / MTU / 驱动 reset 会让绑定失效，必须有 Tier 3 看守（P-7） |
| D-11 | **禁止新增 legacy `struct bpf_map_def`** | libbpf 1.0 已移除；新代码用 BTF `SEC(".maps")` |
| D-12 | **禁止任何探测失败路径以报错退出代替回落** | 可选后端的失败必须是降级，不能让用户因为换了张网卡就起不来 |

---

## §6 验收

### X-1 / X-2（可立即验收）

1. 全树只有**一份**包解析器、**一份**策略判定。
2. `sb_dp_classify` 单测覆盖：v4/v6、TCP/UDP、bypass 命中/未命中、learned_direct 过期/未过期、分片。
3. **mark 断言**：构造一个命中 `destination_bypass` 的包，断言返回 `TC_ACT_OK` 且 `skb->mark` 未被修改。
4. `bpftool prog show` 只有预期的程序，无 embed 但未加载的死 `.o`。
5. 业务门禁 Google 204 / YouTube 200；`redirect_failures=0`、`peer_misses=0`。
6. geoip-cn 直连流量实测可达（这是 D-2 的回归测试，必须有客户端侧证据）。

### X-3（仅在实现后适用）

7. P-1..P-7 各有一条明确日志，失败路径确实回落到 TC 而非退出。
8. **探测层可脱离硬件验收**：对构造的 `IFLA_XDP_FEATURES` 位图做单测，覆盖「REDIRECT 缺失」「ZC 缺失」「RX_SG 置位」「位图不存在（旧内核）」四种情形。
9. **性能门必须在多队列物理机上与 TC 后端 A/B**，且必须分别报告 **带宽** 与 **小包 PPS**（64B / 128B）。带宽不升是预期的（C-6）；**小包 PPS 不升则判定不采纳**。
10. Tier 3 回归：跑 `ethtool -L <if> combined N` 改队列数，断言后端 detach 并回落 TC，流量不中断。
11. `fill_starved == 0` 持续 10 分钟。
12. 注意：rc49 的 v4 ≥15.5 Gbit/s @ ≤14% CPU、v6 splice ON 15765 / 线速 15810 Mbit/s 是**旧基线**；rc50 之后的吞吐 A/B 至今未补证，不得直接引用为当前性能门。

---

## §7 给 Codex 的一句话指令

**顺序：X-1 → X-2(a) → X-3.1（只做探测层）→ X-3 其余。**

X-1 的分层重构顺手修掉 D-2 那个 mark 污染 bug；X-2(a) 删掉从未被加载的 v2。X-3 的第一步单独拆出来做：`common/ebpf/xdp/probe.go` 那四层探测**不依赖任何数据面代码、可以纯单测验收**，先把它做对，AF_XDP 后端剩下的部分才有一个可信的门。

**不要写驱动兼容表**——能力只能来自 `IFLA_XDP_FEATURES` 和 `bind()` 的返回值（D-6）。
