# 框架需求与边界（smart reload + eBPF in/out）— 2026-08-04 审核版

下游开工单：`docs/ebpf-remaining-work-20260804.md`（W0–W7 剩余工作，rc45b-fix 之后）
代码审核方向：`docs/ebpf-code-review-directions-20260804.md`（Q1–Q14 改进/优化方向与边界，rc46-w1v6c；Q1/Q2 先于 W1、Q4 先于 W0）  
整改实施指南：`docs/ebpf-remediation-guide-20260804.md`（复核 rc47-qfix 的 Q 落地质量 → N1–N10 到行改法 + Q3/Q5 完整方案。**Q2/Q7/Q11 为半改/越界，N1+N2 必须先于 W1 重跑**）

上游合同：
- `docs/ebpf-in-out-framework-master-20260803.md`（总合同）
- `docs/ebpf-outbound-framework-plan-20260803.md`（详设）
- `docs/ebpf-implementation-status-20260803.md`（落地状态，rc43-final）

本文件是**审核结论 + 下一轮开工需求 + 硬边界**。任何 AI/人改动这两块，必须先满足本文件的"必须/禁止"清单，超出清单一律视为越界，直接打回。

---

## 第一部分 · 审核结论（当前代码）

### A. smart reload（已按用户要求拆除无缝层）

已完成（本轮）：

| 项 | 状态 |
|---|---|
| 删除 `smartHistoryPool` 进程级粘连池 | ✅ |
| 删除 `RuntimeEpochLifecycle`（publish/commit/rollback/retire） | ✅ |
| 删除 `loadHistory/flushHistory/releaseHistory` 磁盘历史 | ✅ |
| worker 改 `PostStart()` 启动（与 stock urltest 同相位） | ✅ |
| `history_path` 仅 warn，不再建目录/写盘 | ✅ |
| 测试 `TestSmartWorkerStartsOnPostStart` / `TestSmartHealthIsPerInstance` | ✅ 绿 |

**诚实结论**：被删掉的那层其实早就是死代码——`instance.Close()` 先于新 box 创建，池引用归零即删，无法跨 reload 携带状态。**真正的"节点粘连"来源是 `cache.db` 的手动 pin**（`Start()` → `LoadSelected(tag)` → `SelectOutbound`），其次是 `lastSelected` + `switch_margin=0.08` 与 站点 affinity（10m）。清 pin：

```bash
curl -X PUT -H 'Content-Type: application/json' -d '{"name":""}' http://127.0.0.1:9090/proxies/HK
```

仍需改（按优先级）：

| # | 位置 | 问题 | 要求 |
|---|---|---|---|
| S1 | `protocol/group/smart.go` `rankPooled` | pin 只在 breaker `state=="open"` 时才被绕过；节点"半死"（高延迟/丢包但未触发 3 次失败）时 pin 继续生效 → 用户观感仍是粘连 | pin 存活判定改为"pin 候选的健康分低于最优候选 × (1-`switch_margin`) 且样本数 ≥ `min_samples`"时同样标记 `manualPinUnavailable`，日志给出 `pin bypassed: score`。**不得**删除 pin 语义本身 |
| S2 | `option/group.go:66` `history_path` | 字段仍在 schema，行为已变成 no-op，配置侧无感知 | 保留字段（兼容旧配置），但在 `NewSmart` 的 warn 里明确写 `deprecated since rc44, no effect`；同时在 `docs/` 配置说明标 deprecated。**禁止**直接删字段（会让线上配置 parse 失败） |
| S3 | `adapter/runtimeepoch/`（controller/router_view/dns_view） | 除自身测试外零消费者 | ✅ **已删**（用户批准 2026-08）；保留 `adapter/runtime_epoch.go` 供 adaptive 使用，**禁止**重建 `adapter/runtimeepoch/` 包 |
| S4 | `protocol/group/adaptive/`（epoch + `state_persistence.go` + 进程级 `processExitIdentities`） | 同类粘连机制仍完整存在 | 112 线上不使用 `adaptive_pool`，**本轮不动**。若将来启用 `adaptive_pool`，必须先按 smart 同样口径做一次拆除评审 |
| S5 | `box.go:563` `PublishRuntimeEpochOutbounds` | 现在只服务 adaptive | 保留。**禁止**为了"顺手清理"删掉，否则 adaptive 直接坏 |

### B. eBPF out（模块 B sockmap splice）

已确认修好：`CGO_ENABLED=0` stub 全补齐；`protocol/direct/outbound.go` 无 splice wrapper 残留（P0-2 / 越界-14 关闭）；PERCPU map 按 possible CPU 分配 + 求和；`Bytes()` 持 `b.access.RLock` 防 `detachLocked` UAF；Go 侧 pair 计数改 atomic（不与 BPF 抢 ARRAY）；peer map 改 LRU；`sk_redirect_hash(..., 0)` 固定 egress 语义 + LE 静态断言；verdict-only（attach type=10）运行时探测；v6 fail-open；graceful FIN（禁 `SetLinger(0)`）；splice observability 计数落地。

仍需改：

| # | 严重度 | 位置 | 问题 | 要求 |
|---|---|---|---|---|
| E1 | **P0** | `common/ebpf/splice.go:601` `possibleCPUCount()` | 读 `/sys/devices/system/cpu/possible` 失败时 `return 1`。PERCPU map 的 value 缓冲必须是 `8 × num_possible_cpus()`；返回 1 意味着**内核向 8 字节缓冲写整机 CPU 数份数据 → Go 堆越界写** | 改为 `(int, error)`。失败时：① `PrepareSplice` 直接报错 fail-open（splice 关闭，走用户态）；或 ② 强制 `accounting=false` 且永不 touch bytes map。**禁止**任何"猜 1"的兜底 |
| E2 | **P1** | `protocol/ebpf/splice_bridge.go:106` `injectResidualTCP` | 在 `Activate()`（SOCKHASH insert）**之后**从两端 userspace `Read` 残包再交叉 `Write`。此时内核 verdict 已在重定向新到达的 skb → 用户态读到的"残包"与内核已转发的字节可能**乱序**，属静默数据损坏 | 改为：Activate 后用 `ioctl(FIONREAD)` 检查两端 recvq；`==0` 才继续 splice；`>0` 立即 `pair.Release()` 回退用户态 copy。**禁止**用户态与内核同时搬同一条流的字节 |
| E3 | P1 | `splice_bridge.go:48-52` 注释写 "P0: eBPF inbound only"，`spliceInboundOK` 实际放行 `TypeEBPF/TypeRedirect/TypeTProxy` | 代码比合同宽，注释与实现不一致（越界的典型形态：先扩面再补注释） | 二选一并落文档：① 收回到 `TypeEBPF` only；② 保留三类，但把注释、master §6.1、status 文档同步改写，并在 lab 对 redirect/tproxy 各补一次 `redirects>0` 证据。**禁止**只改注释不补证据 |
| E4 | P1 | `spliceOutboundOK` 放行 `selector/urltest/loadbalance/smart/adaptive_pool` | 从"direct-only"扩到组出站。虽由 bare-TCP unwrap 兜底，但准入面是**硬编码**扩张，配置侧无法收窄 | 允许保留，但必须新增 `outbound_offload.splice.allow_outbound_types`（默认 `["direct"]`）显式白名单；组出站只有在配置显式列出时才放行 |
| E5 | P1 | `common/listener/listener_tcp.go:61-70` | `TCPMultiPath=true` 先 `SetMultipathTCP(true)`，随后 `l.tproxy` 分支**无条件**覆盖为 false → 用户显式配置被静默吞掉（越界-16 只加了注释，范围未收窄） | 改为：`if l.listenOptions.TCPMultiPath { logger.Warn("tcp_multi_path ignored on tproxy listener: SOCKMAP/bpf_sk_assign reject MPTCP") }`；且仅在 eBPF `data_plane=socket_assign` 或 splice 启用时强制关闭，经典 tproxy 无 eBPF 时不动用户配置 |
| E6 | P2 | `common/ebpf/splice.go:246` | 注释 "Prefer PairThenActivate"，**该函数不存在**；且 `SpliceBackend.Pair()` 全仓零调用者 | 删掉误导注释；`Pair()` 要么删，要么改为 `// test-only helper` 并加测试引用 |
| E7 | P2 | `adapter/outbound.go:50-52` `SpliceCapableConn.SpliceReady()` | 全仓无实现者，仅 `splice_bridge.go:391` 做类型断言 | 保留为扩展点但写明 `// extension point: no implementer as of rc43`，或删除。**禁止**为了"让它有用"去给协议出站加实现（那是模块 C 的范围） |
| E8 | P2 | `common/ebpf/native/splice.bpf.c` 枚举 `SB_SPLICE_STAT_PAIRS_CREATED/RELEASED` | BPF 侧从不自增（已改 Go atomic），槽位 0/1 恒为 0 | 加注释说明 0/1 由 userspace 维护、内核保留，避免下一个人误读 metrics |

未验证（不是代码问题，是证据缺口）：

| 项 | 现状 |
|---|---|
| `splice.bpf.o` 与 `*.bpf.c` 字节一致 | macOS 无 `linux/types.h`，**禁止本机 generate** → **必须在 PVE/112 上** `make -C common/ebpf check`（边界 G）并留证 |
| iperf 满速吞吐/CPU 对比 | benchmark 文档已自认小对象 curl 不能证明收益 → 进入模块 A 之前必须补 |
| 116（Alpine，`CONFIG_BPF_STREAM_PARSER` 未开） | verdict-only 仍失败；**不改 116 内核**（用户约束），116 上 splice 必须保持 fail-open 静默禁用 |

---

## 第二部分 · 下一轮框架需求（按优先级冻结）

### R0（先做，阻塞其它一切）
1. E1 修死 `possibleCPUCount` 错误路径。
2. E2 加 `FIONREAD` 门 + 删掉 Activate 后的用户态注入。
3. 112 上 `make -C common/ebpf check` 通过并留证。

### R1（B 收口）
4. E3 决策并同步文档 + 补对应 inbound 类型的 lab 证据。
5. E4 新增 `allow_outbound_types` 白名单，默认 `["direct"]`。
6. E5 MPTCP 覆盖范围收窄 + warn。
7. iperf 报告（splice on/off × 30s，记 Gbits/s 与进程 CPU%）。

### R2（smart 收口）
8. S1 pin 的"半死节点"绕过判据。
9. S2 `history_path` deprecated 文案。

### R3（清理，需用户单独批准）
10. S3 删 `adapter/runtimeepoch/`。
11. E6/E7/E8 注释与死 API 清理。

**模块 A（flow verdict）与模块 C 保持 ⏸**：必须 R0+R1 全绿、iperf 有可测收益、且用户显式开工才动。

---

## 第三部分 · 硬边界（盯死 AI 乱来）

### 边界 A · 数据面
- **A-1** `bpf_sk_redirect_hash` 的 flags 恒为 `0`。任何 `BPF_F_INGRESS` 的改动，直接打回。
- **A-2** 一条流的字节，在任一时刻只能由**内核**或**用户态**其中一方搬运。不存在"两边一起搬"的合法情形（E2 的根因）。
- **A-3** 任何 eBPF 路径失败必须 **fail-open** 到用户态 copy，禁止让 inbound 报错或断连。
- **A-4** 禁止 `SetLinger(0)` / 主动 RST 关闭 spliced pair；只允许 graceful FIN。
- **A-5** IPv6 在 verifier-safe 写法落地前，Go 侧继续拒绝 v6 pair。禁止"先放行看看"。

### 边界 B · 改动范围
- **B-1** 禁止修改 116 的内核/内核配置。
- **B-2** 禁止在 `protocol/direct/` 里加任何无条件 conn wrapper（历史事故：包裹后 `syscall.Conn` 丢失，全量 direct TCP 的 `splice(2)` 失效）。
- **B-3** 未经用户逐项批准，禁止删除/重构 `protocol/group/adaptive/**`、`adapter/runtime_epoch.go`、`box.go` 的 epoch 调用。smart 的拆除**不自动**蔓延到 adaptive。
- **B-4** 禁止删除已上线配置字段（含 `history_path`）；只能 deprecate。
- **B-5** 准入面（inbound 类型、outbound 类型）只能通过**配置白名单**放宽，禁止在代码里硬编码扩张。

### 边界 C · 默认值
- **C-1** `outbound_offload.splice.enabled` 默认 **false**；`verdict.mode` 默认 **off**。
- **C-2** 新增开关一律默认关闭、默认最小面。
- **C-3** accounting 关闭时禁止读写 bytes map（含 idle 判据必须降级为纯 liveness）。

### 边界 D · 证据与文档
- **D-1** 声明"修好了"必须附：`go build ./...` + `CGO_ENABLED=0 go build`（linux 核心包）+ `go test` + 112 lab 的 `redirects>0 / redirect_failures=0 / peer_misses=0` + 应用层成功率（n/n）。
- **D-2** 注释、master 合同、status 文档三者与代码不一致时，**以代码为事实**、以合同为准绳：先决定收窄还是放宽，再三处同步。禁止只改注释掩盖实现扩张。
- **D-3** 任何 `.bpf.o` 变更必须在 **PVE 编译主机**（见边界 G）跑 `make -C common/ebpf check`（或等价 `make ebpf_check`）证明与 `.c` 一致（嵌入的二进制不可信）。**禁止**用 macOS 本机产物充当证据。
- **D-4** 声称有性能收益必须是 iperf/CPU 量化数据；curl 小对象墙钟不作为收益证据。

### 边界 E · 并发与生命周期
- **E-1** 锁序固定 `SplicePair.mu → SpliceBackend.access`，不得反向。
- **E-2** 禁止在持有 `b.access` 时调用 `pair.Release()`。
- **E-3** 任何 pair 的 watchdog 必须能被 `stop`/`ctx` 打断，禁止无限 `EpollWait(-1)`（历史事故：reload 卡死）。
- **E-4** smart 的 worker 只允许在 `PostStart()` 启动、`Close()` 停止，禁止再引入第三种相位。

### 边界 H · 功能模块化（可换基线 · 2026-08-05）

- **H-1** DNS/eBPF 增强按 **M-*** 模块交付（见 `docs/ebpf-feature-modules-20260805.md`），禁止与 smart/adaptive 大分支强耦合成不可 cherry-pick 的巨型 commit。
- **H-2** 新逻辑优先独立文件（如 `protocol/ebpf/dns_*.go`）；`inbound.go` 只留字段与钩子调用。
- **H-3** 模块默认 **off**；两模块不得互相业务依赖（M-dns-kernel-direct ⊥ M-dns-prefill）。

### 边界 G · 构建主机（PVE only · 2026-08-05 用户铁律）

> macOS 开发机**不是** eBPF 编译环境。凡 AI/人在本机起 Docker/Colima/`make generate` 编 `.bpf.o` 或 `with_ebpf` 全量二进制，视为越界，产物作废并清理。

| 项 | 规定 |
|---|---|
| **G-1 编译落点** | `ebpf_generate` / `ebpf_check` / `with_ebpf` + cgo 的 `go build`/`go test`/`sing-box` 矩阵，**只允许**在 **PVE 侧 Linux 主机**执行。首选 lab：**adaptive-vm112**（`Host adaptive-vm112` / `ebpf-splice-lab`）；需要跳板时经 **adaptive-pve**（`10.20.20.3`）。builder VM（`adaptive-builder`）仅当 112 不可用且用户点名时使用。 |
| **G-2 禁止本机** | **禁止**在 macOS 本机：① `make -C common/ebpf generate/check`；② `docker run … clang -target bpfel` / Colima 灌 Ubuntu 编 BPF；③ 本地 `CGO_ENABLED=1 -tags with_ebpf` 产出要交付的二进制或 `.bpf.o`。macOS 无可靠 `linux/types.h`/内核头，产物不可信。 |
| **G-3 源码同步** | 改 `native/*.bpf.c` / `connect_prog.c` / loader 后：本机只改**源码与文档** → `rsync`/`git` 推到 PVE 树 → **在 PVE 上** `make -C common/ebpf generate && make -C common/ebpf check` → 需要时再 `TAGS=with_ebpf` 编测。**禁止**把本机生成的 `.bpf.o` scp 进树当正式产物。 |
| **G-4 产物纪律** | `.bpf.o` **不进 git**（既有规则）。本机若误生成：立即 `make -C common/ebpf clean`（或 `rm -f common/ebpf/native/*.bpf.o`），并停掉相关 Docker/Colima 编译容器。交付物以 PVE 上 `make check` 通过的字节为准。 |
| **G-5 纯 Go 例外** | 不碰 cgo/eBPF 的 option 解析、文档、无 tag 的 `go test` 可在 macOS 跑；一旦需要 `with_ebpf`、cgo 或嵌入 `.bpf.o`，回到 **G-1**。 |
与 D-3 的关系：D-3 要求「有 check 证据」；**G 规定 check/generate 的执行主机必须是 PVE 侧 Linux，不是开发者 macOS。**

**G-6 命令备忘（PVE / vm112）：**

```bash
# 跳板示例
ssh adaptive-pve
ssh adaptive-vm112   # 或 ProxyJump adaptive-pve
cd /path/to/a51-beta4-adaptive
make -C common/ebpf generate
make -C common/ebpf check
CGO_ENABLED=1 go test -tags with_ebpf ./common/ebpf ./protocol/ebpf ./include
```

---

## 第四部分 · rc45-ac 复审（模块 A flow verdict + C.1）— 2026-08-04

### 4.1 已确认关闭（代码级复核，非口头）

| 项 | 证据 |
|---|---|
| E1 | `common/ebpf/splice.go` `possibleCPUCount() (int, error)`；`PrepareSplice` 在 `accounting=true` 且探测失败时报错 fail-open，`accounting=false` 时 `cpus=0` 且 `zeroPerCPUBytes`/`sumPerCPUBytes` 直接 return（C-3 落地） |
| E2 | `splice_bridge.go` `drainTCPRecvTo` ×2 → `tcpRecvQueueLen`(TIOCINQ)`==0` 门 → `Activate()`；`injectResidualTCP` 已删。A-2 成立 |
| E2 回归 | `releaseLocked` 加 `if p.activated` 才关 socket——pre-Activate 回退保留 socket 给用户态 copy（rc44c 的 RST 事故根因已修） |
| E3 | `spliceInboundOK` 收窄为 `inboundType == C.TypeEBPF`（选择"收回"而非"扩面+补注释"，符合 D-2） |
| E4 | `option.EBPFSpliceOptions.AllowOutboundTypes` + `newOutboundCoordinator` 空表默认 `["direct"]` + attach 日志打印白名单（B-5 成立） |
| E6/E7/E8 | 误导注释已改；`Pair()` 标 helper；`SpliceCapableConn` 标 extension point |
| S1/S2/S3 | pin 半死绕过判据、`history_path` deprecated 文案、`adapter/runtimeepoch/` 删除 |
| ABI 锁 | C 侧 `_Static_assert` 24/16/8 + Go 侧 `TestOutVerdictABI` `unsafe.Sizeof` 双向锁 |

`gofmt -l` 脏文件（纯格式，非阻塞）：`common/ebpf/verdict_stub.go`、`protocol/ebpf/outbound.go`、`protocol/ebpf/verdict_learn.go`。

### 4.2 新增必改项（模块 A）— rc45b-fix 已关

| # | 严重度 | 要求 | 状态 |
|---|---|---|---|
| A1 | **P0** | `monotonicExpireNs` 禁止 wall fallback；失败放弃 Put | ✅ rc45b-fix |
| A2 | **P0** | BPF `hits/expired/gen_mismatch` + runtime_stats 周期日志 | ✅ |
| A3 | **P1** | destination 级 key 文档/日志声明；默认 off | ✅ 选 ② |
| A4 | **P1** | learn 仅 `InboundType==ebpf` | ✅ conn.go + coordinator |
| A5 | P2 | `MaxEntries` 接入 map create | ✅ |
| A6 | P2 | 删除 port wildcard 假注释 | ✅ |
| A7 | P2 | udp4 无 UDP 写入者注释 | ✅ |
| A8 | P2 | `emit_self_listen_redirect_bypass_v4` 消费 map | ✅ |

### 4.3 残留窗口（已知、非本轮必修）

`tcpRecvQueueLen()==0` 与 `Activate()` 之间到达的字节不会被 sk_skb 二次处理。`accounting=true` 时 byte-idle watchdog 会回收该 pair；`accounting=false` 时只剩 2s liveness 探测，这类连接可能挂死。建议 splice 启用时强制 `accounting=true`，或 Activate 后再做一次 FIONREAD 复核（>0 即 Release + graceful FIN，让客户端重试）。

### 4.4 模块 A 边界（新增，与第三部分同等效力）

- **F-1** `verdict.mode` 默认 **off**；在 A2（内核 hit 计数）落地前，禁止任何非 off 的默认值、禁止在示例配置里开启。
- **F-2** verdict 条目必须可过期、可失效。禁止任何路径写出"无法过期"的 `expire_ns`（A1 的根因）。
- **F-3** 学习写入只允许来自 **eBPF inbound** 且 **空 DirectDialer** 的连接。禁止放宽到组出站或其它 inbound。
- **F-4** 禁止在 verdict 命中路径上做任何 redirect/rewrite；命中只能表现为"return 1 不捕获"。
- **F-5** 声明 verdict 有效必须附：内核 `hits>0` + 应用层 n/n 成功 + `InvalidateAll` 后 `hits` 停止增长的三段证据。curl 通了不算。

### 4.5 Claude 复审 follow-up（rc45c-f5）— 2026-08-04

| # | 问题 | 处理 |
|---|---|---|
| F-5 gap | lab sniff 导致 learn 全 skip，E2E 10/10 未证 kernel bypass | ✅ 修 `verdictIsEmptyDirect`（stock DIRECT `IsEmpty` 假阴性）+ `allow_with_sniff` 压测：`kernel_hits=34/31`，n/n 30/30；`expired=1`（ttl=3s） |
| metrics 静默 | 全 0 时 `vStats==last` 永不打日志 | ✅ 首次 sample 强制输出 |
| residual §4.3 | Activate 后 race | ✅ post-Activate FIONREAD 复核 + splice 强制 accounting |

F-5 摘录（112 journal）：

```
learn wrote DIRECT: 10.20.20.3:18080
verdict metrics: writes=1, skips=0, kernel_hits=34, expired=0, gen_mismatch=0
verdict metrics: writes=2, skips=0, kernel_hits=31, expired=1, gen_mismatch=0
```
