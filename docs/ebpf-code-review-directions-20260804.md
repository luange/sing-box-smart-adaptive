# eBPF in/out 代码审核：改进方向与框架修改建议（2026-08-04）

审核对象：`work/a51-beta4-adaptive` 当前树（版本串 `rc46-w1v6c`，以文件 mtime 为准，树内无 git 无法出 diff）  
上游合同：`docs/framework-requirements-boundaries-20260804.md`（含边界 A/B/C/D/E + 模块 A 边界 F-1..F-5）  
功能缺口工单：`docs/ebpf-remaining-work-20260804.md`（W0–W7）

**本文与 W0–W7 的关系**：W 系列是"功能没做完"；本文是"已经写完的代码里，哪里写法要改"。两者不重叠，
但 **Q2 是 W1（v6 内核 miss）的头号可疑根因**，**Q4 是 W0（v4 长稳 learn）的头号可疑根因**，
所以本文里的 Q1–Q4 应当 **先于** W0/W1 的实验动手，否则实验会把代码缺陷当成内核问题去查。

审核范围：`common/ebpf/{verdict.go,splice.go,abi.go,backend.go,native/connect_prog.c,native/splice.bpf.c}`、
`protocol/ebpf/{inbound.go,outbound.go,verdict_learn.go,splice_bridge.go,runtime_stats.go}`、`route/conn.go`。

---

## 1. 结论摘要

| 编号 | 位置 | 类别 | 影响 | 优先级 |
|---|---|---|---|---|
| Q1 | `protocol/ebpf/inbound.go:78,526` | 并发正确性 | `outboundCoord` 无锁读写，Close 与连接协程竞态 | **P0** |
| Q2 | `protocol/ebpf/inbound.go:731-741` | 设计缺陷 | `InterfaceUpdated` 无条件 `InvalidateAll`，IPv6 环境下等于持续清空 verdict | **P0** |
| Q3 | `protocol/ebpf/verdict_learn.go:85-98` | 设计缺陷 | sniff 门控用 metadata 反推，开 sniff 即永久 skip，模块 A 实际价值≈0 | **P0** |
| Q4 | `protocol/ebpf/verdict_learn.go:131-152` | 正确性 | 优先取 peer 地址，与 connect4/6 看到的 `user_ip` 不一致 → key 永不命中 | **P0** |
| Q5 | `protocol/ebpf/splice_bridge.go:158,183-255` | 资源模型 | 每 pair 2–3 goroutine + 2s 探活 + 独立 epoll fd；`max_pairs` 默认 65536 | P1 |
| Q6 | `protocol/ebpf/splice_bridge.go:76-136` | 性能/顺序 | 先写 4 个 map 项再做 6 次 FIONREAD 门控，拒绝时 6 次 delete 回滚 | P1 |
| Q7 | `splice_bridge.go:408-447,449`、`splice.go:557` | 性能/重复 | 每次尝试 2×64KiB 缓冲 + 4 个 `map[net.Conn]` 去环；unwrap 实现重复 3 份 | P1 |
| Q8 | `protocol/ebpf/outbound.go:202`、`common/ebpf/verdict.go:231-241` | 收尾语义 | `InvalidateAll` 错误被丢；`Close()` 只在本地 `enabled=false` 不写 control | P1 |
| Q9 | `common/ebpf/verdict.go:127-142,209-218` | 性能 | 环形日志用 O(n) 整体位移；`Export()` 无生产消费者 | P2 |
| Q10 | `common/ebpf/splice.go:524-555` | 一致性 | 统计下标硬编码 2..5；出错时返回半填充结构 | P2 |
| Q11 | `protocol/ebpf/outbound.go:245-285` | 健壮性 | `max_pairs` / `verdict.max_entries` 无上限校验 | P2 |
| Q12 | `protocol/ebpf/runtime_stats.go` | 可观测性 | 只有日志、5 分钟粒度，F-5 取证靠 grep | P2 |
| Q13 | 状态文档 | 卫生 | 状态表与"明确未完成"需持续对齐（gofmt 本轮已清） | P2 |
| Q14 | `protocol/ebpf/splice_bridge.go:428-443` | 边角 | 读错误分支落空，坏连接会被当成"已排空" | P2 |

---

## 2. 逐项：现象 / 为什么是问题 / 修改方向 / 边界 / 验收

### Q1（P0）`outboundCoord` 数据竞态

**现象**：`protocol/ebpf/inbound.go:78` 的 `outboundCoord *outboundCoordinator` 是裸字段。
写：`closeOutboundOffload()`（`inbound.go:522-527`）在 Close 时置 `nil`。
读：`MaybeLearnTCP`（`inbound.go:537`）、`TrySpliceTCP`（`inbound.go:553`）、`InterfaceUpdated`（`inbound.go:733`）、
`verdictRuntimeStats`/`spliceRuntimeStats`（`protocol/ebpf/runtime_stats.go:115,151`）。
这些读发生在任意连接协程与统计协程里。对照：同一结构里的 `backend` 字段是用 `backendAccess` RWMutex 保护的（`inbound.go:698-706`）。

**为什么是问题**：reload/关停与在途连接天然并发，`-race` 下必报；实际风险是读到半个指针后走进空对象。
这不是理论问题——splice 的 pair 释放回调、watchdog 都可能在 Close 之后才跑到这里。

**修改方向**：不要在 Close 里把指针置 `nil`。
`outboundCoordinator.Close()` 本身已经在 `c.access` 下把 `splice`/`verdict` 置 nil 并让 `Splice()`/`Verdict()` 返回 nil，
即"关停后所有入口自然变成 no-op"这件事已经在协调器内部做对了。因此：
`closeOutboundOffload()` 只调 `Close()`，保留指针；协调器内部加一个 `closed bool`（`c.access` 保护），
`enabled()`/`verdictEnabled()` 在 closed 时返回 false，`Close()` 幂等。

**边界**：
- 只改这一处生命周期语义，**不得**顺手重构 `Start/Close` 调用顺序或把 `outboundCoord` 挪进 backend。
- **不得**用"加个全局锁"解决——`MaybeLearnTCP` 在每条连接的热路径上，不能引入新的全局互斥。
- 保持 `closeOutboundOffload()` 的返回值语义（错误仍要汇入 `E.Errors`）。

**验收**：`go test -race -tags with_ebpf ./protocol/ebpf ./common/ebpf` 绿；112 上 reload 3 次、每次带在途连接，无 panic、无 `-race` 报告。

---

### Q2（P0）verdict 失效风暴：`InterfaceUpdated` 无条件 `InvalidateAll`

**现象**：`inbound.go:719-741`：
```go
if i.bypassRuleSetStarted {
    updated, err := i.refreshBypassRuleSetsLocked(false)   // 这里已经算出"有没有真的变"
    ...
}
i.bypassRuleSetAccess.Unlock()
if i.outboundCoord != nil {
    if v := i.outboundCoord.Verdict(); v != nil {
        if err := v.InvalidateAll(); err != nil { ... }     // 但这里不看 updated，无条件 bump generation
    }
}
```

**为什么是问题**：`InvalidateAll` 会 `generation++`，使**全部**已学 DIRECT 条目在内核侧变成 gen 不匹配。
`InterfaceUpdated` 在 sing-box 里由网络监听器驱动，IPv6 环境（SLAAC / RA / temporary address 轮换 / 前缀续租）
触发频率远高于 v4。TTL 默认 5 分钟，而 RA 抖动可能是秒级——**结果是条目还没被第二条连接用到就已经失效**。

**这直接是 W1 的头号可疑根因**：状态文档记录 v6 "PutDIRECT 成功、内核 lookup miss、v4 同进程 `kernel_hits` 仍增长"。
v4/v6 的 key 构造在 `connect_prog.c` 里逐字段等价（`emit_flow_verdict_bypass_v4:823-850` 与
`emit_flow_verdict_bypass_v6:930-965`：同一个 `emit_zero_region`、同样的 `ENDIAN_OP(...,16)` 端序处理、
同样的 24B 布局，只差 `family` 与 4 个 addr 字），R4/R5 也在 `1008-1010` 恢复了。
静态看 **key 字节没有明显不对齐**，所以在做逐字节 dump 之前，应先排除"条目被 generation 清掉了"。

**决定性分诊（零成本，counter 已经有了）**：在 v6 复现时同时看一条日志三个数：
- `writes>0` 且 `kernel_hits=0` 且 `gen_mismatch=0` 且 `expired=0` → 内核**根本没查到条目** = 纯 key miss，才去做字节 diff（W1 原路径）。
- `gen_mismatch>0` → 条目查到了但 generation 不符 = **本项 Q2**，与 key 无关。
- `expired>0` → TTL/时钟问题，查 `monotonicExpireNs`。

**修改方向**：
1. 把失效降级为"只在真的变了才失效"：把 verdict 失效放进 `updated == true` 分支，
   或用一个独立的"本机地址/默认路由指纹"（已有 `localInterfacePrefixes` 计算逻辑可复用）做哈希比较，指纹不变则不失效。
2. 加节流上限：单位时间内 `InvalidateAll` 次数超过阈值（例如 1 次/30s）时降为 Warn 计数而非继续 bump，
   避免 RA 风暴把 generation 打成滚水。
3. `InvalidateAll` 成功路径的 Info 日志里带上"触发原因"（interface-updated / close / manual），
   否则日志上无法区分是谁清的。

**边界**：
- **不得**为了"减少失效"而放宽失效条件到"地址变了也不失效"——F-2/F-5 要求条目必须可被失效，
  漏失效比多失效危险得多。允许的优化只有"确认没变时不失效"。
- **不得**改 generation 的语义（仍是 u32、0 跳过、bump 即全量失效）。
- **不得**把失效改成异步/延迟执行。
- 节流只允许作用在"无变化的重复触发"上；只要指纹变了就必须立即失效，不受节流限制。

**验收**：112 上 `ip -6 addr` 人为触发一次地址变化 → 日志出现一次带原因的 `InvalidateAll`；
静置 10 分钟无地址变化 → `InvalidateAll` 次数为 0（当前实现会随 RA 反复出现）；
随后 W1 复现时 `gen_mismatch` 不再增长，此时 `kernel_hits` 若仍为 0 才进入 key 字节 diff。

---

### Q3（P0）learn 门控用 metadata 反推 sniff，导致模块 A 在真实配置下不可用

**现象**：`verdict_learn.go:85-98`：
```go
func verdictUsedSniff(metadata adapter.InboundContext) bool {
    if metadata.Protocol != "" || metadata.Client != "" || metadata.SniffHost != "" { return true }
    ...
}
```
`metadata.Protocol` 只要**开了 sniff 并且识别出协议**就会被填，与"路由决策是否真的用了域名"无关。

**为什么是问题**：绝大多数真实配置都开 sniff。于是 `evaluateVerdictLearn` 恒返回 `verdictSkipSniff`，
`writes` 永远为 0，`skips` 一路涨——这正是 lab 里 `kernel_hits=0` 的一个已知直接原因
（状态文档也记了"lab 配置有 sniff 时常 skip learn"）。换句话说：**模块 A 目前只在"关掉 sniff"这种不现实的配置下才生效**。
而 `allow_with_sniff=true` 这个逃生口是"直接关掉安全门"，不是解法——它会把"按域名分流"的流量学成 DIRECT，
一旦命中就是**静默绕过分流规则**，属于 F-4 明确要防的事故。

**修改方向（设计层，这是模块 A 能否上生产的分水岭）**：
判据必须来自**路由决策本身**，而不是 metadata 的存在性。落地形态（按代价从低到高，建议选 1）：
1. **路由匹配侧打标**：在规则匹配处记录本次决策实际使用过的条件类别（domain / protocol / process / user / geosite …），
   放进 `InboundContext` 的一个新字段（例如 `RouteMatchInputs` 位掩码）。
   learn 只在"掩码里不含任何域名/进程/用户类输入"时允许写。默认位掩码为"未知"，未知 = 不允许写（保守）。
2. **决策指纹比对**：learn 前用**纯 IP:port**（清空 Domain/Protocol/User/ProcessInfo 的 metadata 副本）重跑一次路由匹配，
   结果与真实决策一致才允许写。语义最强但每连接一次 dry-run，成本高，且要保证 dry-run 无副作用（不得触发 DNS、不得计数）。
3. 保持现状 + 文档承认"模块 A 仅适用于无 sniff 部署"，`mode` 永久默认 off。

**边界**：
- **默认必须变严不变松**：新字段缺省值必须导致"不允许 learn"。任何"拿不到信息就当作没用域名"的写法直接打回。
- 方案 1 允许新增 `adapter.InboundContext` 字段与 route 侧赋值，但 **不得** 改动任何现有路由匹配语义、
  不得改规则优先级、不得因为打标而改变 `metadata` 已有字段的取值。
- 方案 2 必须证明 dry-run 无副作用（不发 DNS、不动 cache、不写统计），否则不许上。
- **不得**扩大 `allow_with_sniff` 的作用范围，也不得把它变成默认 true。它只保留为"实验室强制开关"。
- 无论选哪个方案，port 53 / process / user 三道门（`verdict_learn.go:66-81`）原样保留。

**验收**：sniff 开启的常规配置下，同一 `dst_ip:port` 重复连接 ≥200 次：
`writes>0`、`kernel_hits` 增长、且**存在一条按域名分流的规则时**该域名对应的 IP 不出现在 `Export()` 里（负样本必须过）。

---

### Q4（P0）`resolveLearnDestination` 取址优先级与内核侧看到的地址不一致

**现象**：`verdict_learn.go:131-152` 优先返回 `remoteAddr`（已建立连接的 peer 地址），只有它无效时才用 `metadata.Destination`。

**为什么是问题**：内核 `connect4`/`connect6` 的 verdict 查表用的是 `bpf_sock_addr.user_ip*` +`user_port`，
即**客户端应用当初 dial 的目标地址**。而 `remoteConn.RemoteAddr()` 是**本进程 direct 出站真正连上的地址**。
两者在"目标是域名、由 sing-box 解析"或 `DestinationAddresses` 改写的场景下不同 → 写进 map 的 key 永远等不到匹配的查表。
即使当前 lab 用纯 IP 测（两者相同）看不出来，一旦真实使用就是"写了一堆永不命中的条目"，
并且因为 LRU 有容量，还会挤掉可能命中的条目。

**修改方向**：把优先级调正——**首选 `metadata.Destination`（IP 形态时）**，其次 `DestinationAddresses[0]+Destination.Port`，
最后才回落 peer 地址；并且当"首选来源与 peer 地址不一致"时不写（说明中间发生了改写，内核看到的和我们连上的不是一回事），
计一个 skip 原因（新增 `verdictSkipAddrMismatch`）便于取证。
`metadata.Destination` 是域名形态时，本来就该被 Q3 的门控拦住，这里不需要再猜。

**边界**：
- **不得**为了"多学几条"而在地址不一致时两边都写。一个 flow 只允许一个 key。
- 新增的 skip 原因只加常量与计数，**不得**改 `VerdictStats` 结构体字段（ABI 双锁的 `Skips` 保持单一计数器，
  细分原因只走 Debug 日志）。
- **不得**改 `route/conn.go` 的 hook 位置或传参（`remoteAP` 继续传，仅用于一致性校验）。

**验收**：`verdict_learn_test.go` 补三个用例——纯 IP 目标（写）、域名目标+DNS 改写（不写且 skip 原因为 addr-mismatch/sniff）、
`DestinationAddresses` 改写后与 peer 不一致（不写）。112 上 W0 实验 `kernel_hits` 增长。

---

### Q5（P1）splice 每 pair 的 goroutine / 探活 / epoll 资源模型

**现象**：`splice_bridge.go:158` 每个 pair 起 `watchSplicePair`，其中 `startSpliceEpollWatch`（`:257`）再起 1 个 goroutine
并**独占一个 epoll fd**；外层还有一个 select 转发 goroutine（`:195-203`）。
`watchSplicePair` 内有两个 ticker：`liveTick` 固定 2s（`:215`），每次对两端各做一次 `SO_ERROR` + 一次 `TCP_INFO` getsockopt
（`tcpConnAlive:332-376`）；`ticker` 为 `idle/2`。`max_pairs` 默认 65536（`outbound.go:126-129`）。

**为什么是问题**：满载时 ≈13 万 goroutine、6.5 万 epoll fd、每 2 秒 26 万次 getsockopt。
模块 B 的卖点就是"把数据面交给内核以省 CPU"，控制面这样写会把省下来的 CPU 还回去，
而且 fd 数很容易撞上进程 `RLIMIT_NOFILE`，撞上之后 `EpollCreate1` 失败 → 退化成纯 ticker 探活（静默降级）。

**修改方向（架构级）**：把 watchdog 从 per-pair 改成 **backend 级单实例**：
- `SpliceBackend` 持有**一个** epoll fd；`Activate()` 成功后把两端 fd 注册进去（`EPOLLRDHUP|EPOLLHUP|EPOLLERR`），
  `Release()` 时注销（fd 关闭本身也会自动移除）；维护 `fd → *SplicePair` 映射。
- 一个 goroutine 跑 `EpollWait`，事件触发即 `Release` 对应 pair。EPOLLRDHUP/HUP/ERR 覆盖了 `liveTick` 想抓的绝大多数状态，
  **`liveTick` 可以整体删除或降到 30s 兜底**。
- 字节空闲检测（§4.3 要求，不能删）改成 **一个** 定时 goroutine 按 `idle/2` 遍历 pair 快照，逐个读 PERCPU 字节数。

**边界**：
- **不得**削弱 §4.3 的字节空闲兜底：Activate↔FIONREAD 残窗依赖它，`accounting` 强制开启（`outbound.go:130-135`）也必须保留。
- **不得**改动 A-2 两阶段协议（BeginPair → flush → drain → FIONREAD → Activate）与 `Release` 语义
  （未 Activate 不关 socket、只 FIN 不 RST）。
- epoll 注册失败仍必须 fail-open（退化到定时扫描），**并且要打一条 Warn**，不许静默降级。
- 遍历 pair 快照时**不得**长时间持 `b.access`：先拷贝切片再逐个处理，避免阻塞 `BeginPair`/`Release`。
- **不得**顺手改 `max_pairs` 默认值（已上线字段语义）；容量问题用资源模型解决，不靠降默认值掩盖。

**验收**：112 上 500 条并发长连接：goroutine 数 ≈ 常数 + O(1)/pair（用 `/debug/pprof/goroutine` 计数对比改前改后）；
epoll fd 数为 1；v4 iperf 回归 ≥15.5 Gbits/s @ ≤14% CPU；杀掉一端后 pair 在 1s 内释放（`pairs_released` 增长）。

---

### Q6（P1）splice 尝试路径：先写 map 再做门控

**现象**：`splice_bridge.go:76` 先 `BeginPair`（内部 2 次 peer map update + 2 次 PERCPU 清零 update，`splice.go:303-317`），
之后才做 flush / `refuseIfBuffered`×2 / `drainTCPRecvTo`×2 / FIONREAD×2；任一失败就 `Release`，
而 `Release` 会做 6 次 map delete（`splice.go:449-454`）。

**为什么是问题**：在"多数连接最终被拒"的现实分布下（TLS fragment、非 direct 出站、有缓存数据、recvq 非空），
每条被拒连接白付 4 次 map 写 + 6 次 map 删。这些是 bpf syscall，不是内存操作。

**修改方向**：把**不依赖 map 状态**的门控全部前移到 `BeginPair` 之前：
`refuseIfBuffered`×2 与首轮 FIONREAD 检查（"两端 recvq 是否已经为空"）可以先做；
只有需要"把缓存写给对端"的 flush/drain 才必须在有 peer 表之后（实际上 flush/drain 是纯 userspace TCP 写，
不依赖 peer 表——**可以确认后一并前移**，peer 表只服务于 Activate 之后的内核转发）。
Activate 之后的那次 FIONREAD 复查（`:127-136`）必须原样保留。

**边界**：
- **不得**删除任何一道门（inbound 白名单、outbound 白名单、裸 TCP、TLS fragment/spoof、buffered、recvq 空、post-Activate 复查）。
- **不得**把 post-Activate 复查前移或合并——它是 §4.3 残窗的唯一同步防线。
- 顺序调整必须在注释里重写"为什么这一步可以在 BeginPair 之前"，并且证明 flush/drain 在没有 peer 表时语义不变。
- **不得**为了省 syscall 而缓存/复用 `spliceKey`→map 项（生命周期与 socket 绑定，复用会串流）。

**验收**：拒绝路径的 bpf syscall 数降为 0（`strace -f -e trace=bpf` 计数，构造一个 `tls_fragment=true` 的连接）；
112 上 112 项 E2E 全绿；v4 iperf 回归不劣化。

---

### Q7（P1）每次尝试的堆分配与三份重复的 unwrap

**现象**：
- `drainTCPRecvTo`（`splice_bridge.go:408-447`）在 FIONREAD 之前就 `make([]byte, 64*1024)`，两个方向 = 每次尝试 128 KiB，
  而绝大多数情况下 `n<=0` 立即返回。
- `unwrapTCPConn`（`splice.go:557`）、`spliceTCPFromConn`（`splice_bridge.go:449`）、`flushCachedToRemote`（`:487`）、
  `refuseIfBuffered`（`:539`）各自 `make(map[net.Conn]struct{})` 做去环 = 每次尝试 4 个 map，
  而链深实际只有 2–4 层。
- 三处 unwrap 逻辑近乎重复（`Upstream()` / `NetConn()` / `*net.TCPConn`），已经出现"一处支持 `SpliceCapableConn` 另一处不支持"的分叉。

**修改方向**：
1. `drainTCPRecvTo` 惰性分配：先 FIONREAD，`n<=0` 直接返回；需要时再取缓冲，并用 `sync.Pool` 或按 `min(n, 64KiB)` 分配。
2. 去环改成深度上限循环（`for depth := 0; depth < 16; depth++`），删掉 4 个 map。
3. 抽一个 `walkConnChain(conn net.Conn, fn func(net.Conn) bool)` 统一遍历，
   `spliceTCPFromConn` / `flushCachedToRemote` / `refuseIfBuffered` / `unwrapTCPConn` 都走它。

**边界**：
- 统一 helper **不得**改变各调用点现有的判定顺序与返回语义（尤其 `spliceTCPFromConn` 里 `SpliceCapableConn` 优先于 `*net.TCPConn`）。
- `common/ebpf` 与 `protocol/ebpf` 的分层不许打破：helper 放在使用侧（`protocol/ebpf`），
  `common/ebpf/splice.go` 的 `unwrapTCPConn` 若要复用需通过参数注入，**不得**让 `common/ebpf` 反向依赖 `protocol/ebpf`。
- 深度上限必须显式常量 + 注释，越界视为"链太深，拒绝 splice"（fail-open），不许静默取最后一个。

**验收**：`go test -bench` 或一次 `-benchmem` 微基准显示拒绝路径 allocs/op 明显下降；行为测试（含 `SpliceCapableConn` 桩）不变。

---

### Q8（P1）收尾语义：失效错误被丢、`Close()` 不写 control

**现象**：
- `outbound.go:200-204`：`_ = verdict.InvalidateAll()` —— 错误被丢弃且无日志。
- `verdict.go:231-241`：`Close()` 把 `verdictMap/controlMap/statsMap` 置 -1、`enabled=false`，
  但**没有把 `enabled=0` 写进 control map**。

**为什么是问题**：map fd 的所有者是 inbound `Backend`，协调器 Close 与 backend Close 之间存在一个窗口，
窗口里内核程序仍会读 control。当前靠 `InvalidateAll()` 的 generation bump 兜住（所以不是 P0），
但一旦 `InvalidateAll` 失败且错误被丢，就退化成"窗口内仍有生效的 DIRECT 旁路而用户态已无主"——正是 F-2/F-4 要防的形态。

**修改方向**：`Close()` 内部在置 -1 之前 best-effort 做一次 `enabled=0` 的 control 写；
`outbound.go` 的 `InvalidateAll` 错误必须 Warn（带 generation），失败时额外尝试 `SetEnabled(false)`。
两者都是 best-effort，不允许因此让 Close 返回错误而阻断关停。

**边界**：
- **不得**在协调器里去关 map fd（所有权仍属 inbound `Backend`）。
- **不得**改 Close 的调用顺序或让 Close 变成可失败（fail-open 优先于报错）。
- 顺序必须是"先让内核停止旁路（enabled=0 / generation bump），再释放引用"，不许反过来。

**验收**：单测覆盖"Close 后 control map 内容为 `enabled=0`"（可用假 fd/内存桩）；
112 上关停日志能看到 `InvalidateAll generation=N` 或明确的 Warn，二者必有其一。

---

### Q9（P2）`recordExport` 的 O(n) 位移 + `Export()` 无消费者

**现象**：`verdict.go:138-141`
```go
if len(v.exportLog) >= verdictExportCap { v.exportLog = append(v.exportLog[:0], v.exportLog[1:]...) }
```
满 256 条后**每次写**都整体前移 255 条，且在 `exportAccess` 互斥内、位于 learn 热路径（每条新连接一次）。
`Export()`（`:209`）目前只有测试消费。

**修改方向**：改成定长数组 + `head`/`count` 的真环形缓冲，`Export()` 按顺序拷出；
或把记录整体收进"仅当 logger 为 Debug 时才记"的开关后面。

**边界**：`Export()` / `VerdictEntry` 是导出 API，**只改内部实现，不得删除或改签名**（测试与将来取证要用）。
`verdictExportCap` 不得增大（内存上限是设计的一部分）。

---

### Q10（P2）splice 统计下标硬编码 + 半填充返回

**现象**：`splice.go:538-552` 用 `for i := 2; i < 6` 和 `switch i { case 2: ... }` 直接写内核统计下标，
与模块 A 用命名常量（`outVerdictStatHits` 等）的写法不一致；
且中途 `lookupMap` 出错时返回**已部分填充**的 `stats` + err，调用方（`runtime_stats.go:157-160`）整包丢弃。

**修改方向**：把 `sb_splice_stat_*` 下标在 `common/ebpf/outbound_abi.go` 里定义成命名常量并加一条与头文件对齐的断言测试；
出错时返回零值结构 + err（避免"半真"数据被将来某个调用方当成真值用）。

**边界**：**不得**改内核侧统计数组的下标含义或长度（ABI）；只在 Go 侧命名与错误语义上收口。

---

### Q11（P2）容量参数缺上限

**现象**：`normalizeOutboundOffloadOptions`（`outbound.go:268-270`）只校验 `max_pairs >= 16`，无上限；
`verdict.max_entries` 在 Go 侧完全不校验（下限 16 在 C 里兜，`create_out_verdict_map`）。

**修改方向**：两者都加上限并 clamp + Warn（不要报错，避免把已上线配置变成启动失败）。
量级建议与 map 内存占用挂钩说明（每条 verdict entry 40B + LRU 开销）。

**边界**：**必须 clamp+Warn，不得改成 return error**（已上线字段不能变成启动阻断，D-2/B-4）。
上限值写成命名常量并在 zh/en 文档标注。

---

### Q12（P2）可观测性只有日志

**现象**：`VerdictStats`/`SpliceStats` 只经 `runtime_stats.go` 打日志，周期 5 分钟（`runtimeStatsInterval`）；
splice 的周期样本还是 Debug 级（`runtime_stats.go:185-189`）。F-5 取证靠 grep 日志。

**修改方向（刻意保守）**：**不新增 HTTP 端点、不新增配置字段**。只做两件事：
1. 与模块 A 已有的"首样本必打 + 变化即打"对齐（`runtime_stats.go:102-108` 那段逻辑），把 splice 的首样本从 Debug 提到 Info；
2. 关键计数器出现**非零增量**时（`redirect_failures`、`peer_misses`、`gen_mismatch`）用 Warn 打出来，
   而不是等 5 分钟周期。

**边界**：
- **不得**新增 Clash API / metrics 端点或新配置项（会触发新的兼容承诺）。
- **不得**缩短 `runtimeStatsInterval` 常量（日志量是生产约束）；只允许"事件驱动补一条"。
- 计数器语义与字段名不许改。

---

### Q13（P2）代码卫生与文档同步

- `gofmt -l common/ebpf protocol/ebpf` 本轮已为空（rc45b 时报的三个文件已修）。**规则保留**：
  后续 PR 必须保持为空，且**不得**顺带 format 无关文件（尤其 `protocol/group/adaptive/**`）。
- `docs/ebpf-implementation-status-20260803.md` 的"总览"表与"明确未完成"表必须始终一致；
  本轮已经对齐（W1 = ◐ + follow-up）。**规则**：任何一行从 ◐ 改成 ✅，必须同时删掉"明确未完成"里对应行，
  并在同一次提交里附上 F-5 三项证据的日志片段。

---

### Q14（P2）`drainTCPRecvTo` 的错误分支落空

**现象**：`splice_bridge.go:428-443`：当 `nr > 0` 且 `rerr` 既不是 timeout 也不是 `io.EOF` 时，
三个 `if` 都不成立 → 继续下一轮循环 → 下一次 FIONREAD 很可能返回 0 → 函数返回 `nil`（"排空成功"），
但这条连接实际上已经出错。

**修改方向**：显式处理"`nr>0` 且 `rerr` 为真实错误"→ 返回该错误（调用方会 fail-open 到用户态，语义正确）。
同时把 `SetReadDeadline(50ms)` 的选择写进注释：为什么 50ms、为什么移交内核前一定要 `SetReadDeadline(time.Time{})` 复位。

**边界**：**不得**把这里改成"忽略错误继续 Activate"。任何不确定状态都必须 fail-open 回用户态。

---

## 3. 三条架构级方向（比逐条修更重要）

**方向 A：控制面从 per-connection 结构改为 backend 级事件驱动**（对应 Q5/Q6/Q7）。
现在的写法是"每条连接一套完整机制"（goroutine + epoll + ticker + 缓冲 + 4 个 map + 若干 bpf syscall）。
模块 B 要在生产上站住，控制面开销必须与 pair 数解耦：一个 epoll、一个扫描器、零拒绝成本。
**边界**：数据面协议（A-2 两阶段 + FIONREAD 门 + post-Activate 复查 + FIN-only 释放）一个字都不能改。

**方向 B：learn 的正确性必须由路由决策提供，而不是由 metadata 反推**（对应 Q3/Q4）。
这是模块 A 的生死线。当前实现在"开 sniff"时恒 skip、在"域名目标"时写错 key——
两个方向都指向同一个结论：**learn 需要一个来自路由层的、明确的"本次决策只用了 IP:port"信号**。
在拿到这个信号之前，`verdict.mode` 必须保持默认 off（F-1），并且文档要写清"仅适用于无 sniff 部署"。
**边界**：默认永远变严；未知即拒绝；负样本（按域名分流的目标不得被学成 DIRECT）必须进测试。

**方向 C：可观测性以"证据可复现"为目标，而不是以"接口更多"为目标**（对应 Q12/Q10/Q8）。
F-5 要求的三项证据（`kernel_hits>0`、n/n、失效后停增）应当**只看日志就能拿到**，
所以要做的是"事件驱动补日志 + 计数器语义收口"，而不是加 API。
**边界**：不新增端点、不新增字段、不改计数器语义。

---

## 4. 统一边界清单（"优化"不得成为扩权借口）

1. **ABI 冻结**：`sb_out_verdict_key/value/control`（24/16/8B）、`sb_splice_key`（40B）尺寸与字段序不得变；
   任何触碰都要同时更新 C 侧 `_Static_assert` 与 Go 侧 `unsafe.Sizeof` 测试（双锁）。
2. **v4 路径不回归**：`emit_ipv4_*` / `emit_flow_verdict_bypass_v4` / v4 splice 行为不得因任何优化改变；
   每个 PR 附 v4 iperf（≥15.5 Gbits/s @ ≤14% CPU）与 112 项 E2E 结果。
3. **安全门只增不减**：本文所有优化不得删除或前移任何一道门（尤其 post-Activate FIONREAD 复查、port 53、process/user、
   empty DirectDialer、inbound/outbound 白名单）。
4. **fail-open 不变**：任何新增失败分支都必须回落到用户态复制或"不旁路"，不得 abort 连接、不得 RST。
5. **默认值不变**：`verdict.mode=off`、`half_close=close`、`allow_outbound_types=["direct"]`、`max_pairs=65536` 保持；
   容量问题用实现解决，不靠改默认值掩盖。
6. **不新增配置字段 / HTTP 端点**（Q3 方案 1 的 `InboundContext` 内部字段不算配置，但需在 PR 说明里点名）。
7. **不删除已上线字段与导出 API**：`Export()`、`Pair()`、`VerdictEntry`、`history_path` 等只能改内部实现或 deprecate。
8. **禁区不动**：116 的内核与内核配置；`protocol/direct/` 内任何无条件 conn wrapper；
   未经逐项批准不动 `protocol/group/adaptive/**`、`adapter/runtime_epoch.go`、`box.go` 的 epoch 调用。
9. **一条 Q 一个 PR**（Q1+Q2 可同 PR 但分 commit，因为都在 `inbound.go` 生命周期段）。
   每个 PR 回答三问：改了哪些 map/ABI；fail-open 线在哪一行；哪个计数器能证明它有效。
10. **性能类改动必须给出改前/改后数字**（goroutine 数、allocs/op、bpf syscall 数、iperf、CPU%），
    只有描述没有数字的性能 PR 直接打回。

---

## 5. 建议顺序

```
Q1 + Q2（同一段生命周期代码，先修）      ← 阻断 W1 误诊
  └─ 然后再跑 W1 的 v6 复现：先看 gen_mismatch，再决定要不要做 key 字节 diff
Q4（一行优先级 + 一致性校验）             ← 阻断 W0 误诊
  └─ 然后跑 W0 的 200 连接实验
Q3（设计层，需要 route 侧配合，独立评审）  ← 模块 A 能否上生产
Q5 → Q6 → Q7（模块 B 控制面三连，带数字）
Q8 → Q10 → Q11 → Q14（收口）
Q9 / Q12 / Q13（低风险卫生）
```

W2/W3/W4/W5 与本文各项互不阻塞，可并行。W6（C.2 结论）已关闭，W7（C.3 UDP）保持冻结。
