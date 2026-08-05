# eBPF In/Out 剩余工作清单（可直接开工版）— 2026-08-04

**基线**：rc48-nfix（见 `docs/ebpf-implementation-status-20260803.md`）。  
R0–R2 + A1–A8 + W0/W2–W6 已推进；**Q 复核 N1–N10 已落地**；Q3 P1 / Q5 step1 已做。  
**仍 open**：无（计划内可闭环项已完成）。**冻结**：C.3、DNS prefill、TC 全量引擎、116 内核。**已关闭**：Q3 P2–P4、Q5 step2–3、W1 v6 F-5、Phase 0 矩阵。  
合同：`docs/framework-requirements-boundaries-20260804.md` §4。  
并行：`docs/ebpf-code-review-directions-20260804.md`、`docs/ebpf-remediation-guide-20260804.md`。
整改实施指南：`docs/ebpf-remediation-guide-20260804.md`（rc47-qfix 复核：**Q2/Q7 半改、Q11 越界**；N1–N10 到行改法）。

**上游合同**（本文件不覆盖、只补充）：
- `docs/ebpf-in-out-framework-master-20260803.md`（总合同）
- `docs/ebpf-outbound-framework-plan-20260803.md`（详设，§5 = 模块 C 范围）
- `docs/framework-requirements-boundaries-20260804.md`（硬边界 A/B/C/D/E + F）

---

## 0. 通用规则（每一项都适用，违反即打回）

- **G-1 顺序不可乱**：W0 是所有 OUT-A 相关工作的前置。W0 未拿到证据前，禁止动 W1（v6 verdict）。
- **G-2 一次一项**：一个 PR/一轮只做一个 W 编号。禁止"顺手把 W4 也做了"。
- **G-3 默认关闭**：新增任何开关默认 off / 最小面（边界 C-2）。
- **G-4 fail-open**：任何新 BPF 路径失败必须退回用户态，禁止让 inbound 报错或断连（边界 A-3）。
- **G-5 ABI 双向锁**：改任何 map 的 key/value 结构，必须同时更新
  `singbox_ebpf_out.h` 的 `_Static_assert` 和 Go 侧 `unsafe.Sizeof` 测试。只改一侧 = 打回。
- **G-6 `.bpf.o` 必须在 112 跑 `make -C common/ebpf check`**（边界 D-3）。嵌入的二进制不可信。
- **G-7 交付证据固定四件**：`go build ./...` + `CGO_ENABLED=0 GOOS=linux go build`（核心包）+
  `go test`（相关包）+ 112 lab 计数器截图/日志。缺一件视为未完成（边界 D-1）。
- **G-8 不许改的东西**：116 内核（B-1）、`protocol/direct/` 加 wrapper（B-2）、
  `protocol/group/adaptive/**`（B-3）、已上线配置字段（B-4，只能 deprecate）。

---

## W0 · OUT-A 实证（P0）✅ 关闭（rc45c + rc49 Q3 复证）

### 现状
`kernel_hits` 至今恒 `0`。lab 配置带 sniff → `evaluateVerdictLearn` 命中 sniff gate →
`backend.Skip()` → 从未 `PutDIRECT`。因此"E2E learn 10/10"只证明了"挂载不崩 + 安全门有效"，
**没有证明内核 bypass 真的会发生、会正确过期、会被 generation 正确失效**。

### 要做的（代码为零，环境+验证为主）
1. 112 起一份 **sniff-free** learn 配置：
   - inbound `type: ebpf`，`outbound_offload.verdict.mode: "learn"`，`ttl: 60s`（便于观测过期）
   - 路由命中**空 direct 出站**（无 `bind_interface` / `routing_mark` / detour）
   - **关闭 sniff**（`sniff: false` 或不配 sniff 规则），目标端口 ≠ 53
   - 压测目标：PVE 10.20.20.3 的 HTTP，同一 `dst_ip:port` **重复连接 ≥ 200 次**
     （第 1 次走用户态学习，第 2 次起应命中内核 bypass）
2. 采集 `eBPF outbound verdict metrics` 三轮：压测中 / `InvalidateAll` 后 / 恢复 `off` 后。

### 验收（F-5，三条全绿才算通过）
| # | 判据 | 含义 |
|---|---|---|
| 1 | `kernel_hits > 0` 且随连接数增长 | bypass 真的在内核发生 |
| 2 | 应用层 **n/n** 成功（n ≥ 200） | bypass 没打错流、没破坏连接 |
| 3 | 触发 `InvalidateAll`（interface update 或 reload）后 `kernel_hits` **停止增长**、`gen_mismatch` 开始增长 | 失效链路有效 |
| 4 | 等 `ttl` 过后再连，`expired` 增长 | TTL 过期链路有效 |

### 如果 W0 失败（`kernel_hits` 仍为 0）
按此顺序排查，**不要**先改代码：
1. `verdict metrics` 的 `writes` 是否 > 0？= 0 → 还是被 gate 掉了，看 debug 日志的 `skip: reason=`
   （对照 `verdict_learn.go` 的 `verdictSkip*` 常量）。
2. `writes > 0` 但 `kernel_hits = 0` → 内核侧查表 miss。可能原因按概率排序：
   a. key 的 `port` 字节序（Go 写 host-order，BPF `BPF_ENDIAN_OP(reg,16)`）不一致；
   b. Go 学到的是 `remote` 的实际 peer 地址，而 connect4 看到的是**用户请求的原始地址**——
      两者在有 DNS/DestinationAddresses 改写时不同，`resolveLearnDestination` 优先取 peer 就会写错 key；
   c. `emit_flow_verdict_bypass_v4` 的插入点在 `emit_ipv4_destination_bypass` 之后，
      若该流已被更早的 bypass 分支吃掉，verdict 永远轮不到。
3. 上述 2b 是**最可能**的真实 bug：请在 W0 里顺带验证一次
   "learn 写入的 key" 与 "connect4 查表的 key" 是否逐字节相同（`Export()` 打印 vs BPF 侧临时 stat 槽）。

### 边界
- 压测期间禁止把 `verdict.mode` 写进任何示例配置 / 默认值（F-1）。
- 压测完必须恢复 `mode: off` 并留一次 `off` 状态的 E2E 证据。

---

## W1 · 纯 IPv6 verdict 查表（P1）✅ 关闭（rc49 lab kernel_hits=150）

### 现状
只有 `emit_flow_verdict_bypass_v4`，在 connect4 与 v4mapped 分支调用。
`connect_prog.c:2149` 注释明写 "Pure IPv6 verdict lookup deferred"。纯 v6 流量永远走用户态。

### 设计（**ABI 不用改**）
`sb_out_verdict_key` 的 `addr[16]` 已足够装 v6，`family` 字段区分 `AF_INET`(2)/`AF_INET6`(10)。
所以只需要新增一个发射函数，Go 侧只需在 `makeOutVerdictKey` 里让 `putAddress` 正确填 v6（已支持）。

新增 `emit_flow_verdict_bypass_v6()`，与 v4 版同构，差异只有三处：

1. **family** 写 `AF_INET6` 而不是 `AF_INET`。
2. **地址**：v6 程序里 `user_ip6` 的四个字（32-bit）分别在 **R7 / R8 / R9 / R4**
   （见 `connect_prog.c:2093-2096`），端口在 **R5**（不是 v4 路径的 R8）。
   按 4 次 `BPF_STX_MEM(BPF_W, ...)` 写入 `STACK_VERDICT_KEY + offsetof(addr) + 0/4/8/12`，
   网络序原样存（与 Go `putAddress` 一致）。
3. **寄存器恢复（关键，v4 版没这个问题）**：`emit_flow_verdict_bypass_v4` 的注释说
   "Clobbers R0-R5"。在 v6 路径上 **R4 装着地址第 4 个字、R5 装着端口**，被 clobber 后
   下游 `emit_ipv6_cidr_bypass` / `emit_redirect_update_and_rewrite_v6_*` 会读到垃圾。
   → v6 版必须在返回前**重新从 `BPF_REG_6` 加载 R4/R5**（照抄 `connect_prog.c:2144-2145` 那两条），
   或改用 R1/R2/R3 做临时寄存器完全不碰 R4/R5。**这是本项最容易出的错，先写对再谈跑通。**

**插入点**：`connect_prog.c:2176` `emit_ipv6_destination_bypass` 之后、
`emit_ipv6_cidr_bypass` 之前——与 v4 路径的相对顺序完全一致（destination bypass → verdict → CIDR）。

**栈**：复用现有 `STACK_VERDICT_KEY(-304, 24B)` / `STACK_VERDICT_SCRATCH(-312, 8B)`，
不要新开槽位（-304..-281 与 `STACK_STATS_KEY(-280)` 紧邻，越界会踩 stats key）。

**learn 侧**：`resolveLearnDestination` / `PutDIRECT` 对 v6 已经是通的（`putAddress` 支持 16B），
去掉的只是内核查表。确认 `MaybeLearnTCP` 不会因 v6 被别的 gate 挡掉。

### 验收
- `make -C common/ebpf check` 通过（G-6）。
- 112 上纯 v6 目标（用 PVE 的 v6 地址或 lab 内 ULA）压测：`kernel_hits` 对 v6 目标增长。
- **v4 回归**：W0 的四条判据在 v6 改动后重跑一次全绿（证明没打坏 v4 路径的寄存器）。
- 新增/更新 `TestOutVerdictABI` 不需要改（ABI 未变）——如果你发现需要改 ABI，说明设计走偏了，停下来先说。

### 边界
- 禁止为 v6 新增第二张 map（"v6 专用 verdict map"）。同一张 LRU + `family` 区分。
- 禁止顺手改 `emit_ipv4_*` 任何一行（G-2）。

---

## W2 · 纯 IPv6 splice pair（P1，v6 性能收益的主体）

### 现状
`common/ebpf/splice.go:615-617` 直接拒绝 v6：`"splice ipv6 pending verifier-safe bpf path"`。
`splice.bpf.c:126` `fill_splice_key_v4` 对 `skb->family != AF_INET` 返回 -1 → `SK_PASS` 走用户态。
原因记录为 "lab 6.12 rejects the v6 ctx access pattern with EACCES on PROG_LOAD"。

### 设计
1. **先定位 EACCES 的真因，不要盲改**。`__sk_buff` 的 `local_ip6` / `remote_ip6` 是 `__u32[4]`，
   verifier 只接受**下标为常量的整字（32-bit）访问**。EACCES 通常来自：
   - 用 `__builtin_memcpy(dst, skb->remote_ip6, 16)` 一次拷 16B（不合法）→ 必须拆成 4 次
     `key->remote_addr` 的 `__u32` 写入，源是 `skb->remote_ip6[0..3]` 四次独立读；
   - 在同一个程序里同时访问 `local_ip4` 和 `local_ip6`，且没有先按 `skb->family` 分支隔离
     → 把 v4/v6 拆成两个 `if (family == AF_INET) {...} else if (family == AF_INET6) {...}`
       完全独立的块，各自只碰自己那组字段；
   - `#pragma clang loop unroll(full)` 的循环里做 ctx 访问（当前 v4 版的循环只写 key 栈内存，合法；
     v6 版**不要**把 ctx 读放进循环）。
   先在 112 上用最小复现程序确认哪一种，把 `bpftool prog load` 的 verifier log 贴进 lab 文档。
2. `fill_splice_key_v4` 改名 `fill_splice_key`，内部按 `family` 双分支，v6 分支写
   `key->family = AF_INET6` + 4×4B 地址 + 同样的 `remote_port >> 16` + `bswap16` 处理。
3. Go 侧 `splice.go:615` 的拒绝改为：仅当**内核探测显示 v6 程序加载失败**时才拒 v6
   （沿用现有 verdict-only 那套运行时探测的思路），加载成功则放行 v6 pair。
4. `sb_splice_key` 是 40B 且 `_Static_assert` 已锁，**ABI 不用改**。

### 验收
- verifier log 证据（EACCES 真因）写进 `docs/ebpf-splice-lab-112.md`。
- `make check` 通过。
- 112 上 v6 iperf3：`redirects > 0`、`redirect_failures = 0`、`peer_misses = 0`，
  且 v6 吞吐/CPU 相对 splice off 有可测收益（边界 D-4：必须是 iperf 数据，curl 不算）。
- **v4 回归**：v4 iperf 数字不劣于当前基线（15.5 Gbits/s @ 14% CPU）。
- 116 上仍然静默 fail-open（不得因为 v6 改动让 116 报错）。

### 边界
- **A-1**：`sk_redirect_hash` 的 flags 恒为 `0`，v6 分支同样。
- **A-5** 在本项完成前继续有效；本项就是解除 A-5 的唯一合法途径。解除必须有 verifier log + iperf 双证据。
- 禁止为了绕过 verifier 改用 `sk_msg`（合同 §6.1 明确 sk_skb）。

---

## W3 · `verdict.mode = "dns"` 定性（P2，二选一，必须选一个）

### 现状
`mode: "dns"` 在 enum 里，但实现是"打一条 warn 然后回落成 learn"
（`verdict_learn.go:176-181`）。配置面暴露了一个名不副实的值。

### 方案 A（推荐，成本低）：删掉这个枚举值
- `option/ebpf.go` 的 `enum:"off,learn,dns"` 改成 `enum:"off,learn"`；
  `normalizeOutboundOffloadOptions` 对 `"dns"` 直接**报错**并给出迁移提示。
- **B-4 不适用**：`dns` 这个**枚举值**从未在任何线上配置里启用过（112 一直是 `off`），
  删的是值不是字段，不会让已有配置 parse 失败。如果你不能确认线上没人用，就走方案 B。
- 删掉 `dnsModeWarned` 字段和相关分支。

### 方案 B：真做 router dry-run
- 需要 router 暴露"给定 `(dst_ip, port, domain?)` 返回将命中的出站"的**只读、无副作用**接口。
- 在 `MaybeLearnTCP` 之外新增一条路径：DNS 应答落地时对每个 A/AAAA 记录 dry-run，
  命中空 direct 才写 DIRECT。
- 额外风险：dry-run 与真实路由的任何不一致 = 静默泄漏。必须有"dry-run 结果与实际出站不符"的
  计数器 + warn，且该计数器非零时自动 `SetEnabled(false)`。
- 这条路成本远高于 W1/W2，**不建议现在做**。

### 验收
- 选 A：`go test ./option` 绿；`docs/configuration/inbound/ebpf.md` + `.zh.md` 同步；
  status 文档把"dns 模式"从"未做"改为"已移除，理由 X"。
- 选 B：上面那个不一致计数器必须有 lab 证据。

### 边界
- 禁止保持现状（名不副实的枚举值就是 D-2 违例：配置面承诺了实现没有的行为）。

---

## W4 · `half_close: "passthrough"` 定性（P2）

### 现状
文档写 `passthrough` = "disables splice until half-close can be forwarded faithfully"，
即这个值的实际语义是"整段不 splice"。**它不是一个 half-close 策略，它是一个 splice 开关。**

### 要做的（二选一）
- **A（推荐）**：承认它是开关，重命名语义并在文档里写清"`passthrough` 目前等价于不启用 splice；
  保留字段值以便将来实现真半关转发"。同时 `startSplice` 在 `half_close == "passthrough"` 时
  直接 `logger.Info("splice disabled: half_close=passthrough (true half-close forwarding not implemented)")`
  并不 attach——**当前是否真的不 attach 要先核实**，如果现在是 attach 了但每条流都拒，属于白耗资源。
- **B**：实现真半关：一侧 FIN 后只关那一侧的 SOCKHASH 方向，另一侧继续 splice。
  需要 `sk_skb` 侧感知 FIN 并单向删 peer 条目，复杂度中等，收益仅限半关协议（少见）。建议不做。

### 验收
- 选 A：`half_close=passthrough` 时日志明确、`splice attached` 不出现、`pairs_created` 恒 0。

---

## W5 · 配置文档与 schema 同步（P2，但现在就有缺口）

### 现状缺口（已核实）
| 项 | 状态 |
|---|---|
| `docs/configuration/inbound/ebpf.md` | ✅ `outbound_offload` 章节完整（splice + verdict + 安全门 + A3 粒度声明） |
| `docs/configuration/inbound/ebpf.zh.md` | ❌ **完全没有 `outbound_offload` 章节** |
| `docs/schema.json` | ❌ ebpf inbound 条目里 `outbound_offload` **出现 0 次**，JSON schema 校验会把合法配置判为未知字段 |
| `docs/manual/misc/ebpf-inbound-comparison.zh.md` | ❌ "直连流量 / 代理流量"两行仍是 module B/A 之前的描述 |

### 要做的
1. `ebpf.zh.md` 按英文版 1:1 补 `outbound_offload` 章节（含 A3 粒度警告、F-1 默认 off、安全门四条）。
2. `docs/schema.json` 给 ebpf inbound 加 `outbound_offload` 的完整 object schema
   （`splice`: enabled/max_pairs/accounting/half_close/idle_timeout/allow_outbound_types；
   `verdict`: mode enum/ttl/max_entries/allow_with_sniff）。注意 W3 的结论决定 mode 的 enum 取值。
3. `ebpf-inbound-comparison.zh.md` 按实际落地改写，并标注"v6 未 offload""verdict 默认 off"。

### 边界
- schema 里 `verdict.mode` 的 enum 必须与 `option/ebpf.go` 的 tag 逐字一致。
- 禁止在文档示例里出现 `"mode": "learn"`（F-1）。

---

## W6 · 模块 C.2：出站 mark / bind 下沉（P2，独立立项）

### 范围（照抄详设 §5.2，不得扩张）
多 WAN 场景把 `routing_mark` / `bind_interface` 写进一张 map，由
`cgroup/sock_create` 统一打 `SO_MARK`，替代 Go 侧逐 dialer 设置。收益是
"新加 dialer 忘记设置"这类 bug 消失。

### 设计要点
- 新 map：`sb_out_sockopt`（key = 出站身份，value = `{mark u32, ifindex u32, flags u32}`）。
  key 怎么定是本项的核心设计问题——**先出设计再写码**，因为 `sock_create` 阶段
  **拿不到目标地址**，只有 cgroup + uid + 协议。这意味着 per-outbound 的 mark 下沉
  在 `sock_create` 上**可能根本做不到**（一个进程的所有 socket 长一样）。
  → 如果结论是做不到，本项应当**关闭而不是硬做**，把结论写进文档。
- 边界 A-3 同样适用：map 缺条目 = 不打 mark = 回退 Go 侧行为，禁止拒绝建 socket。
- 合同 §193 明确：**禁止引入 `routing_mark`/`table` 之外的新内核级全局副作用**。

### 验收
- 先交一份可行性结论（能做/不能做 + 理由），再谈实现。
- 若实现：多 WAN lab 上"Go 侧不设 mark，仅靠 BPF 下沉"的流量走对出口 + `ip rule` 命中计数。

---

## W7 · 模块 C.3：UDP direct offload（P3，明确不在本框架内）

详设 §5.3 自己写了："复杂度接近重写 shared_network 的一半，**建议单独立项，不要塞进本框架的 P2**"。

**结论：本轮不做。** 需要 TC egress + conntrack map。开工前必须先有独立的框架文档 +
用户显式批准。任何人在 W0–W6 期间碰这块 = 越界。

---

## 8. 优先级与依赖图

```
W0 (OUT-A 实证) ──┬─→ W1 (v6 verdict)
                  └─→ [OUT-A 定性：能用 / 该删]
W2 (v6 splice) ── 独立，可与 W0 并行（不依赖 verdict）
W3 (dns 枚举)  ── 独立，1 小时级
W4 (passthrough)── 独立，1 小时级
W5 (文档/schema)── 独立，随时可做
W6 (C.2)       ── 先出可行性结论
W7 (C.3)       ── 冻结
```

**建议开工顺序**：W3 + W4 + W5（当天可清）→ W0（等环境）→ W2（收益最大）→ W1 → W6 结论。

---

## 9. 每项交付时必须回答的三个问题

1. **动了哪些 map / ABI？** 有则贴 `_Static_assert` 与 Go 测试的双向证据（G-5）。
2. **失败时会怎样？** 必须能指到具体的 fail-open 代码行（G-4）。
3. **哪条计数器能证明它真的生效了？** 说不出计数器名字 = 没做完（D-1/D-4/F-5）。
