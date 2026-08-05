# sing-box eBPF In/Out 总框架与施工边界（治理文档 / 交给 grok·codex 的合同）

> 版本：2026-08-03　适用源码树：`work/a51-beta4-adaptive`
> 下游详设：出站三模块的细节在 [`ebpf-outbound-framework-plan-20260803.md`](ebpf-outbound-framework-plan-20260803.md)，本文是它的上位治理文档。
> **本文优先级最高。凡本文与下游详设/代码注释/AI 自己的判断冲突，以本文为准。**

---

## 0. 这份文档是干什么的

你（实现方，无论是 grok、codex 还是人）拿到的是一份**合同**，不是"设计灵感"。

- 里面所有写着 **【铁律】** 的条目，不可违反、不可"优化"、不可"我觉得这样更好"。要改，先回来改本文并说明理由，得到确认后再动代码。
- 里面所有 **【禁止】** 的动作，出现即判定实现错误，直接回退。
- 里面的 **ABI 表、map 类型、内核版本门、验收标准**，是逐字生效的。不许"差不多"。
- 凡遇到本文没覆盖的判断点，**默认动作是停下来问**，不是自己拍板。宁可少做，不许乱做。

判断"AI 乱来"的唯一标准：**它做了本文没授权的事**。授权范围之外的一切自由发挥都算越界。

---

## 1. 全局铁律（in / out 都适用，最高优先级）

### 1.1 ABI 锁 —— 结构体布局是硬约定，不是实现细节

- 【铁律】所有跨 内核↔用户态 的结构体，字段顺序、大小、padding 全部由 `_Static_assert` 锁定（见 `native/singbox_ebpf.h:66-71`、`native/shared_network.h` 的 offset 断言）。**新增结构体必须同样加 `_Static_assert`**，否则不许提交。
- 【铁律】Go 侧镜像结构体（`common/ebpf/abi.go`）必须与 C 端逐字节对应，并在 `abi_test.go` 里加 `unsafe.Sizeof` 断言。改了 C 不改 Go、或反之，即错误。
- 【铁律】ABI 里的**字节序**：端口一律主机序（host order）存取（现状：`control->bridge_port` 全程主机序，Go 侧用 `netip.Port()` 主机序写 key）。地址一律网络序原样 `memcpy`。**禁止**在某个新字段上擅自换序。
- 【禁止】为了"省事"往现有结构体尾部塞字段。现有结构体是满的、被断言锁死的。要带新信息，新开结构体或复用注释里已声明的复用字段（例：ingress ifindex 借用 `socket_cookie` 字段承载，见 `shared_network.bpf.c` `fill_redirect` 注释——这类复用必须有注释说明，不许无声复用）。

### 1.2 加载器与构建 —— 四条不可绕过的既有约束

- 【铁律】本工程**不使用 libbpf、不使用 BTF、不使用 clang 编译 cgroup 类程序**。cgroup 程序（connect/sendmsg/recvmsg/sock_release）由 `native/connect_prog.c` 里的手写指令构建器 `emit_*` 生成；TC 程序由 clang 编译成 `.o` 再由 `native/shared_network_loader.c` 手动重定位加载。**新代码必须沿用既有二选一，禁止引入第四种加载方式。**
- 【铁律】cgo 只编译包目录下的 `.c`。native/ 里的实现文件通过包目录下的 `cgo_*.c` `#include` 进来（见 `common/ebpf/cgo_*.c` 与 `README.md` 的 cgo 边界说明）。新增 native 源文件**必须**配套新增 `cgo_xxx.c` 桥接，否则编不进去。
- 【铁律】`.bpf.o` 由 `make generate` 产出、`make check` 做字节级可复现校验、`go:embed` 嵌入、**不进 git**。新增 TC/sk_skb 类对象必须接进同一套 Makefile 流程和 `make check`。
- 【铁律】**【构建主机 = PVE 侧 Linux only】** `make ebpf_generate` / `ebpf_check` / `with_ebpf`+cgo 的 build/test/**禁止**在开发者 **macOS 本机**（含本机 Docker/Colima）执行。正式编译与 `make check` 只在 **PVE lab**（首选 **vm112** / `adaptive-vm112`，跳板 `adaptive-pve`）完成。macOS 只改源码与文档；误生成的 `.bpf.o` 必须 `make -C common/ebpf clean` 删掉。细则见 `docs/framework-requirements-boundaries-20260804.md` **边界 G**。

### 1.3 手写指令构建器的使用红线

- 【禁止】用 `native/connect_prog.c` 的 `emit_*` 指令构建器去写 `sk_skb` / `sk_msg` / `sock_ops` 程序。指令构建器只服务 cgroup sockaddr/sockopt 类程序。socket-level 程序一律走 clang→`.o`→手动重定位加载器的路线。（这是出站模块 B 最容易被 AI 写歪的点。）
- 【铁律】`shared_network_loader.c` 目前把 prog type 写死成 `BPF_PROG_TYPE_SCHED_CLS`（:275），map 符号名写死在 `shared_network_object_map_fd()`（:74）。要复用它加载出站对象，**必须先做重构**（见 §5），不许在加载器里 `if 文件名 == ...` 打补丁式分叉。

### 1.4 内核版本门 —— 能力不足必须显式降级，禁止静默假设

- 【铁律】每个能力都要在 `checkKernelCapabilities()`（`backend.go:308` 一带）里探测，探测失败要走 `eBPFOperationError()` 给出人话错误，**禁止**"探测不到就当有"。
- 现有基线（记入代码注释，不许口头相传）：
  - cgroup connect/sendmsg 重定向：≈ 4.10+。
  - UDP 启用（依赖 `INET_SOCK_RELEASE` 做连接态 UDP 回收）：≈ **5.9+**。
  - TC clsact + `bpf_sk_assign`（shared_network socket_assign 面）：≈ 5.7+。
  - 出站 SOCKHASH + `bpf_sk_redirect_hash`：≈ 4.18/4.20，且需 `CONFIG_NET_SOCK_MSG` / `CONFIG_BPF_STREAM_PARSER`。
  - 【铁律】上述数字若与实际探测冲突，以**运行时探测**为准，探测不过就降级关掉该面，并 log 说明——绝不带病 attach。

### 1.5 可观测性红线（这条是出站模块 A 的命门）

- 【铁律】任何"绕过用户态"的路径（出站 splice、verdict offload、direct 直连加速），只要它让流量不再进 sing-box 的 route/log/clash-api，就**必须**有对应的计数器 + 周期日志，且必须能被 `RuntimeStats()` 读到。
- 【禁止】新增任何"静默改变路由结果"的逻辑。流量少进一次用户态，就少一次日志和一次策略判定——这是"看起来没问题实则错路由"的头号来源。凡是可能改变流量去向的开关，**默认关**（off），由配置显式打开。

### 1.6 生命周期与回退红线

- 【铁律】`Prepare/Attach/Close` 三段式。`Attach` 之前失败，`Close` 必须能把已建的 map/prog fd 全数回收；`Attach` 中途失败，必须回退已 attach 的 program（参考现有 `attach_runtime_program`/`detach_runtime_program` 与 `UpdateBypassCIDR` 的 IPv6-先-IPv4-后+rollback 模式）。
- 【禁止】留下"半 attach"状态就返回成功。
- 【铁律】所有向内核 map 写入的多步操作（先写 A 再写 B），失败时要按逆序回滚（现状 `sync_token` 在 `shared_token_to_original` 写失败时会回删 `shared_redirect`，见 `shared_network.bpf.c`）。新代码照此办理。

---

## 2. 现有资产地图（禁止重造轮子）

实现方**先读这张表**，凡表中已有的，直接复用，不许另写一份。

| 资产 | 位置 | 复用方式 |
|---|---|---|
| map 创建原语 | `sb_ebpf_create_map`（`bpf_util.c`） | 所有新 map 走它 |
| prog 加载原语 | `sb_ebpf_load_prog`（`bpf_util.c`） | 所有新 prog 走它 |
| attach/detach + owner 追踪 | `sb_ebpf_attach_prog`/`detach_prog`/`detach_owned_progs` | 【注意】attach 第一参数目前叫 cgroup_fd，出站 sockmap attach 目标是 map fd，需泛化成 target_fd（见 §5） |
| 手动 ELF 重定位加载 | `shared_network_loader.c` | 出站 sk_skb 对象复用，但需先泛化 prog type/map 表（§5） |
| Go↔C map 读写 | `lookupMap`/`updateMap`/`updateMapWithFlags`/`deleteMap`（`backend.go:736-769`） | 所有新 map 的 Go 侧读写走它 |
| socket cookie 获取 | `socketCookie`（`backend.go:771`）、`SO_COOKIE` getsockopt | 出站配对用 |
| 错误归一化 | `eBPFOperationError()`（`backend.go`） | 所有对外错误走它 |
| UID/CIDR 策略编译 | `policy.go`（`compileUIDRanges`/`compileBypassCIDRPolicy`/delta） | 出站若需 UID/CIDR 过滤直接复用 |
| 原始目的地读取 | `LookupOriginal`/`TakeOriginal`（`backend.go:629-687`） | 出站配对的入站来源 |
| UDP 客户端/绑定引用计数 | `protocol/ebpf/udp_state.go` | 不要另造 UDP 状态表 |
| 本地路由管理 | `protocol/ebpf/route.go`（RTN_LOCAL/RT_TABLE_LOCAL） | 出站若需本地路由复用 |
| 统计读取骨架 | `runtime_stats.go` + ARRAY map + Go 侧 delta | 新计数器照此加 |

- 【禁止】新写一套 map 读写、一套错误封装、一套 UID 编译、一套 UDP 状态表。发现重复实现即回退。

---

## 3. 顶层架构：两个数据面 + 五个模块

```
                         ┌──────────────────────── sing-box 用户态 ────────────────────────┐
                         │  route / rule-set / logger / clash-api / outbound dial          │
                         └───────▲───────────────────────────────────────────▲─────────────┘
                                 │ 真实 socket（可被 sockmap 接管）             │
   ── eBPF IN（已存在，本次仅审计+必修）──                          ── eBPF OUT（本次新建）──
   ┌─────────────────────────────────────────┐        ┌───────────────────────────────────────┐
   │ IN-1 cgroup 面 (connect_prog.c)          │        │ OUT-B sockmap splice   (P0, 先做)      │
   │   本机出连接重定向进代理                    │        │   client sk ⇆ upstream sk 内核直转      │
   │ IN-2 shared_network 面 (TC clsact)       │        │ OUT-A flow verdict offload (P1)         │
   │   LAN/热点设备透明代理                      │        │   direct/proxy 判决下沉，默认关          │
   └─────────────────────────────────────────┘        │ OUT-C 出站侧 cgroup egress (P2, 可选)   │
                                                       └───────────────────────────────────────┘
```

- 【铁律】实现顺序 **B → A → C**。B 不完成不许碰 A；A 不完成不许碰 C。每个模块独立可开关、独立可回退。
- 【铁律】IN 与 OUT 共用底座（`bpf_util.c`、加载器、map 原语），但**各自的 map/prog 命名空间隔离**，禁止一个模块的 program 去读另一个模块的 map（配对信息只能通过明确定义的 ABI 结构体传递）。

---

## 4. eBPF IN —— 现状、必修项、边界

### 4.1 两个面的职责（不许混淆）

- **IN-1 cgroup 面**：拦截*本机*进程的 `connect/sendmsg/recvmsg`，把目的地改写成 `127.128.0.0/9`（v4 默认）或 IPv6 ULA 前缀内的 token 地址，原始目的地存 map，userspace listener（端口 65532）取回。map：`redirect_map`、`udp_token_map`（HASH）、`udp_peer_map`、`bypass_socket_cookie`（LRU）。回收：TCP 靠 Go `TakeOriginal` 删；UDP 靠 `sock_release` 内核程序删。
- **IN-2 shared_network 面**：TC clsact 挂在下游（热点/LAN）网卡的 ingress/egress，做 token 改写+反向还原，或 `bpf_sk_assign` socket_assign。map 全是 `LRU_HASH`，自淘汰。

### 4.2 必修项（P0，先于任何出站工作）

**IN-FIX-1：`redirect_map` 从 HASH 改 LRU_HASH。**

- 位置：`connect_prog.c:239` `create_redirect_map`，把 `SB_EBPF_HASH_MAP_TYPE`（=1）改为 `SB_EBPF_LRU_HASH_MAP_TYPE`（=9）。
- 根因（已审计确认）：该表是普通 HASH、无 LRU、Go 侧无周期 GC；TCP 条目仅由 `TakeOriginal`（accept 时）删除；`sock_release`（`connect_prog.c:2195`）**只清 UDP**。连接在到达 listener 前中止（RST/扫描/秒关）→ token 条目成孤儿，只增不减，涨满 65536 后 `REDIRECT_DROPS` 递增、TCP 重定向失效。
- 【铁律】只改这一个常量，**不改** key/value 结构、**不改** `emit_redirect_candidate`（:467）的"存在且字段全等则复用、否则算 collision 换 attempt"幂等逻辑。
- 验收：构造 5 万条中止连接的压测后，`redirect_map` 条目数不再单调逼近上限；正常 TCP 连接的 `TakeOriginal` 命中率不变。

**IN-FIX-2（可选、维护性）：合并 `Close()` 与 `cleanupStartFailure()`。**

- 位置：`inbound.go:419` 与 `inbound.go:480`，两者除加锁外逐字节相同。抽 `closeLocked()`，`Close()` 加 `closeAccess.Lock()` 后调用。
- 【铁律】抽取后行为必须与现状**完全一致**（同样的关闭顺序、同样的 `E.Errors` 聚合），只是去重。禁止借机"顺手改逻辑"。

### 4.3 IN 的边界（不许动）

- 【禁止】动 token 地址的生成算法（五元组+socket_cookie 哈希，`emit_ipv4_redirect_token` :537 起）。回程已验证依赖它。
- 【禁止】把 UDP 连接态回收从 `sock_release` 挪到 Go 侧，或反过来。当前"非连接 UDP 走 Go 引用计数 + 连接 UDP 走内核 sock_release"是互补设计（`udp_state.go:112-116`），审计已确认无泄漏。
- 【禁止】把 shared_network 的 LRU_HASH 改成 HASH。

---

## 5. 出站施工的三个前置重构（不做完不许写模块 B）

这三处不改，任何新内核对象**加载不进去**。它们是硬门槛，不是可选优化。

1. **泛化加载器 prog type 与 map 表**（`shared_network_loader.c`）
   - `shared_network_object_load_section()`（:196/:275）把 `BPF_PROG_TYPE_SCHED_CLS` 提成入参。
   - `shared_network_object_map_fd()`（:74）把"符号名→fd"的硬编码表改成由调用方传入的 `{name, fd}` 数组，或每个对象各带一张表。
   - 【禁止】用 `if (strcmp(filename,...))` 在加载器里分叉。要的是参数化，不是打补丁。

2. **Makefile 支持多对象**（`common/ebpf/Makefile`）
   - 现在只有单一 `SOURCE/OBJECT`。改成列表，新增出站 `.bpf.c` 走同一 `generate`/`check`/`clean`，同样 `-target bpfel -O2 -g0`、同样字节级 `make check`。

3. **attach 原语泛化 target_fd**（`sb_ebpf_attach_prog`）
   - 第一参数语义从 cgroup_fd 泛化为 target_fd（sockmap 的 attach 目标是 map fd，不是 cgroup fd）。owner 追踪逻辑保留。
   - 【铁律】泛化后现有 cgroup attach 调用行为不变（回归测试必须全绿）。

- 【铁律】这三步各自独立提交、独立过测，**证明未破坏现有 IN 的加载/attach** 之后，才允许开始模块 B。

---

## 6. eBPF OUT 各模块的 ABI 与边界（详设见下游文档，本文只锁边界）

> 完整 map/prog 清单、Go API、生命周期细节在 [`ebpf-outbound-framework-plan-20260803.md`](ebpf-outbound-framework-plan-20260803.md) §3–§5。本节只列**不可违反的边界**，与详设冲突时以本文为准。

### 6.1 OUT-B：sockmap splice（P0）

- 内核机制：`BPF_MAP_TYPE_SOCKHASH` + `BPF_PROG_TYPE_SK_SKB`（`STREAM_PARSER` + `STREAM_VERDICT`）+ `bpf_sk_redirect_hash(..., 0)`。**flags 必须为 0**（经对端 socket 发到网络）；`BPF_F_INGRESS` 会把 skb 塞进对端接收队列，用户态不读即卡死（sidecar 模型，不是代理转发）。
- 【铁律】**用 sk_skb，不用 sk_msg**。sk_msg 拦的是本地 sendmsg 出口（sidecar 模型），代理转发要的是接收侧。这条已在详设 §3.1 标注，此处再锁一次——这是 AI 最容易选错的点。
- 【铁律】splice 只对**入站交给用户态的是真实 TCP socket**的场景成立（cgroup/shared_network 入站满足；TUN 入站不满足，必须排除）。
- 【铁律】**P0 入站类型仅 `ebpf`**（E3 2026-08-04）。redirect/tproxy 需单独授权 + lab 证据，禁止代码硬编码扩张。
- 【铁律】**出站类型白名单** `outbound_offload.splice.allow_outbound_types`，**默认 `["direct"]`**（E4/B-5）。组出站只有配置显式列出才放行。
- 【铁律】splice 资格链（全满足才 splice，缺一即回退用户态中继）：TCP、双端 bare TCP、入站/出站白名单、无 TLS fragment/spoof、Activate 前两端 recvq（FIONREAD==0）、内核能力探测通过。
- 【铁律】**一条流的字节在任一时刻只能由内核或用户态一方搬运**（A-2）。Activate 后禁止用户态 Read/Write 注入残包。
- 【铁律】splice 上线即"该连接不再进用户态读写"，所以**关闭/半关**必须处理干净：优先 epoll RDHUP 检测，其次 sock_ops + ringbuf 兜底，且**必须有 idle watchdog**。半关（half-close）若无法忠实转发，提供 `half_close: passthrough` 逃生开关退回用户态。禁止 `SetLinger(0)`/RST。
- 【禁止】把 splice 做成默认开。默认关，配置显式开。
- 配对顺序【铁律】：`BeginPair`（peer map）→ flush sniff（用户态 Write）→ recvq 空检查 → `Activate`（SOCKHASH）。详设 §3.4 peer-then-sockhash 语义保留；**禁止** Activate 后用户态交叉搬运。

### 6.2 OUT-A：flow verdict offload（P1）

- 机制：`LRU_HASH` verdict 缓存，key/value 见详设 §4.1（`sb_out_verdict_key` 24B / `sb_out_verdict_value` 16B，加 `_Static_assert`）。
- 【铁律】三种模式 `off / learn / dns`，**默认 off**。`learn` 只旁路学习不改路由；改路由只在明确模式下发生。
- 【铁律】四道安全门（详设 §4.4）一个都不能省：白名单前缀外不判决、TTL 失效、命中即计数、可一键全表失效（invalidate）。
- 【禁止】让 verdict 覆盖用户态显式路由规则。verdict 只在"用户态没有更具体规则"时作为加速旁路。这是"静默错路由"的最高风险模块——§1.5 全程适用。

### 6.3 OUT-C：出站侧 cgroup egress（P2，可选）

- 【铁律】P2，B 和 A 未验收前不许开工。范围严格限定在详设 §5，禁止扩张。

---

## 7. 配置边界

- 【铁律】出站能力挂在**现有 `ebpf` 入站的子配置 `outbound_offload` 下**，**不新增 outbound type**（详设 §2.2）。理由：新 outbound type 会破坏 detour/urltest/ConnectionTracker/clash-api。
- 【铁律】所有出站开关默认关。schema 追加见详设 §6，字段名不许改。
- 【禁止】为出站能力引入需要用户手动配 routing_mark/table 之外的新内核级全局副作用。

---

## 8. 验收标准（每条都要有证据，不接受"应该没问题"）

实现方提交时，逐条附证据（命令输出/日志/计数器截图）。缺证据视为未完成。

测试矩阵（沿用 `common/ebpf/README.md` 约定）：

```bash
# 单元（CGO on / off / race 三种）
go test ./common/ebpf/... ./protocol/ebpf/...
go test -race ./common/ebpf/... ./protocol/ebpf/...
CGO_ENABLED=0 go test ./...

# Android 交叉编译（验证 NDK 头与 cgo 边界）
GOOS=android GOARCH=arm64 CGO_ENABLED=1 go build -tags with_ebpf ./...

# 可复现构建
make -C common/ebpf check   # 字节级一致

# 加载集成（只过 verifier，不 attach）
SING_BOX_EBPF_INTEGRATION=1 SING_BOX_EBPF_SHARED_INTEGRATION=1 go test ./...

# 数据面集成（netns + veth，真实走一遍）
SING_BOX_EBPF_INTEGRATION_ATTACH=1 go test ./...
```

验收清单：

1. IN-FIX-1：redirect_map 为 LRU；孤儿压测后条目数收敛；正常 TCP `TakeOriginal` 命中率不变。
2. §5 三个重构各自独立过测，且**现有 IN 加载/attach 回归全绿**。
3. 每个新结构体都有 `_Static_assert` + Go 侧 `Sizeof` 断言。
4. 每个新 map 走 `sb_ebpf_create_map`，类型与本文/详设表一致（尤其别把该 LRU 的写成 HASH）。
5. 模块 B：netns 内两条回环 TCP 确实走 sockmap 直转（用计数器证明，不看"感觉快了"）；正常关闭、半关、idle 超时三种收尾都被验证。
6. 模块 B：资格链 5 条每条都有"不满足→回退用户态"的用例。
7. 模块 A：默认 off；learn 模式不改路由（用日志证明流量仍进用户态）；四道安全门各有用例；invalidate 生效。
8. 可观测性：每个绕过用户态的路径都有计数器且 `RuntimeStats()` 能读到。
9. 生命周期：Attach 中途失败可完整回退（注入失败点测试）。
10. 内核能力不足时显式降级 + 人话日志，绝不带病 attach。
11. 所有默认开关为关。

---

## 9. "AI 易乱来"点位对照表（review 时逐条打勾）

| # | 易犯错误 | 正确做法 |
|---|---|---|
| 1 | 引入 libbpf/BTF/CO-RE | 【禁止】。沿用手写构建器 + 手动重定位加载器 |
| 2 | 用 `emit_*` 写 sk_skb | 【禁止】。sk_skb 走 clang→.o→加载器 |
| 3 | splice 选 sk_msg 或 redirect_hash(INGRESS) | 【禁止】。用 sk_skb + `bpf_sk_redirect_hash(..., 0)`（egress to net） |
| 4 | 往现有结构体尾部塞字段 | 【禁止】。新结构体 + `_Static_assert` |
| 5 | 新写一套 map 读写/错误封装/UID 编译 | 【禁止】。复用 §2 表 |
| 6 | 出站开关默认开 | 【禁止】。一律默认 off |
| 7 | verdict 覆盖用户态显式规则 | 【禁止】。只在无更具体规则时旁路加速 |
| 8 | 绕过用户态却无计数器 | 【禁止】。必须可观测 |
| 9 | 探测不到能力就当有 | 【禁止】。探测失败即降级 + 日志 |
| 10 | 加载器里按文件名 if 分叉 | 【禁止】。参数化 prog type / map 表 |
| 11 | 把该 LRU 的 map 写成 HASH（或反之） | 对照 §2/§6 的类型表 |
| 12 | 改 token 生成算法 / UDP 回收分工 | 【禁止】。回程已依赖，不许动 |
| 13 | 新 map 只在包目录写 .c 不加 cgo 桥接 | 必须配 `cgo_xxx.c` |
| 14 | 新 .bpf.o 不进 Makefile/make check | 必须接入并可复现 |
| 15 | Attach 半成功就返回成功 | 必须完整回退 |
| 16 | 遇到本文未覆盖的判断自行拍板 | 停下来问 |

---

## 10. 一句话给实现方

**照本文和下游详设逐条做，顺序 IN-FIX → §5 三重构 → B → A → C；每一步先证明没破坏现有 IN，再往前走；所有默认关、所有绕过用户态的路径都要能被看见；本文没授权的，一律不做。**
