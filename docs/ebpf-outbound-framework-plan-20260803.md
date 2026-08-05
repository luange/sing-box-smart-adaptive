# sing-box eBPF 出站（ebpf out）框架设计

日期：2026-08-03
基线源码：`work/a51-beta4-adaptive`（当前 eBPF 入站 + shared_network 已调通的版本）
目标读者：实现者（grok / codex）。本文只做设计与任务拆分，不含实现代码。

---

## 0. 结论先说

**"出站 eBPF" 不是把入站程序方向翻转**。入站的工作是"改写目的地址 + 把流量搬进用户态"；出站已经在用户态里了，eBPF 在出站侧唯一能提供的价值是**让字节不要再经过用户态**。这拆成两个正交能力：

| 模块 | 名称 | 做什么 | 收益场景 |
|---|---|---|---|
| **B** | 数据面下沉 / sockmap splice | 已建立的"字节透明"中继，把 inbound socket 与 outbound socket 在内核里对拼，省掉 2 次拷贝 + 2 次上下文切换 | 高吞吐代理、`direct` 中继、网关转发 |
| **A** | 决策下沉 / flow verdict offload | 把"这条流走 direct"的结论提前写进 map，让 `connect4/6` 与 TC ingress 直接放行，流量**完全不进用户态** | direct 占比高的网关/热点（即 dae 的模式） |
| **C** | 出站侧 cgroup egress | 出站 socket 自动 mark/绑定/防环；UDP direct offload | 多 WAN、策略路由、防环加固 |

**推荐实现顺序：B（P0）→ A（P1）→ C（P2）→ 统计与加固（P3）。**

理由：B 不改变任何路由语义，可按单条连接回退到现有 `bufio.Copy`，风险边界清楚；A 要把"决策"提前到连接建立之前，一旦配置里存在依赖 sniff / domain / user 的规则，就会产生**静默错误分流**，必须显式 opt-in 并加安全门。先做 A 会把正确性风险摊到整个项目上。

现有文档 `docs/manual/misc/ebpf-inbound-comparison.zh.md` 里已经点出了这个缺口：

> 直连流量：只有命中 `bypass_rule_set`/内置绕过时才完全不进用户态；普通 sing-box `direct` 仍经过用户态中继

模块 A 补的是这一行，模块 B 补的是"必须进用户态时也别拷两遍"。

---

## 1. 现状：可复用件与必须改的地方

### 1.1 可直接复用

| 资产 | 位置 | 复用方式 |
|---|---|---|
| BPF 系统调用/加载/attach/清理封装 | `common/ebpf/native/bpf_util.c`；声明在 `native/singbox_ebpf.h:175-190` | 直接调用 `sb_ebpf_create_map` / `sb_ebpf_load_prog` / `sb_ebpf_attach_prog` |
| Go 侧 map 读写原语 | `common/ebpf/backend.go:736-769`（`lookupMap`/`updateMap`/`deleteMap`/`mapOperation`） | 抽到 `common/ebpf/map.go`，出站后端共用 |
| socket cookie 读取 | `common/ebpf/backend.go:771-787` | splice 配对键、防环都要用 |
| 防环 cookie map + `ProtectFunc` | `common/ebpf/backend.go:605-627` | 出站 socket 必须继续注册，否则 splice/offload 都会自环 |
| ELF 重定位加载器 | `common/ebpf/native/shared_network_loader.c:74-93`（符号名→map fd 表）、`:196-296`（加载 section） | 泛化后加载新的 `splice.bpf.o` |
| stats 数组 map + 轮询 | `common/ebpf/runtime_stats.go`、`protocol/ebpf/runtime_stats.go` | 出站计数器照抄这套 |
| bypass CIDR LPM 增量更新 + 回滚 | `common/ebpf/backend.go:460-603` | 模块 A 的 verdict map 增量更新照抄 |
| 构建/校验/测试约定 | `common/ebpf/Makefile`、`common/ebpf/README.md` | 扩展即可 |

### 1.2 必须改造的三处（否则新对象加载不进去）

1. **加载器硬编码程序类型**：`shared_network_loader.c:275` 固定 `BPF_PROG_TYPE_SCHED_CLS`、attach type 固定 0。
   → 给 `shared_network_object_load_section()`（`:196`）加 `prog_type` / `expected_attach_type` 参数；把符号名→map fd 的解析（`:74`）改成传入 `{name, fd}` 表，而不是写死 `shared_*` 字符串。建议把这个文件重命名/拆成 `object_loader.c`，`shared_network_runtime.c` 与新的 `splice_runtime.c` 各自提供自己的 fd 表。
2. **Makefile 只编译一个对象**：`common/ebpf/Makefile` 的 `SOURCE`/`OBJECT` 是单值。
   → 改成列表（`SOURCES := native/shared_network.bpf.c native/splice.bpf.c`），`generate`/`check` 循环处理。根 `Makefile` 的 `ebpf_generate` 目标不用改。
3. **cgroup 程序是手写指令**：`native/connect_prog.c` 是一个 BPF 指令 builder（`emit_*` 系列，2600 行）。
   → **新增的 sk_skb / sock_ops 程序绝对不要走 builder**，写进 `.bpf.c` 用 clang 编译。builder 只在模块 A 需要往现有 `connect4/6` 链上插一次 map 查询时才动（新增一个 `emit_flow_verdict_bypass()`，形状和 `emit_ipv4_cidr_bypass()`（`connect_prog.c:763`）完全一样）。

### 1.3 入站数据面回顾（模块 B 的配对来源）

- 本机路径：`cgroup/connect4|6` + `sendmsg/recvmsg` 把目的地址改写成 `127.128.0.0/9` 内的 token 地址，原目标存 `tcp_redirect`/`udp_redirect` map；listener 在 65532 上 accept 后用 `TakeOriginal()` 取回原目标（`protocol/ebpf/inbound.go:663-687`）。
- 共享网络路径：TC ingress 走 `token` 或 `socket_assign` 两种数据面（`protocol/ebpf/shared_network.go:39-232`）。
- **关键事实**：无论哪条路径，进到用户态时 sing-box 手上都是一个**真正的 TCP socket**（不是 tun 上的伪连接）。这是 sockmap splice 可行的前提；TUN 入站没有这个前提，因此模块 B 只对 `ebpf` / `redirect` / `tproxy` / `shared_network` 入站生效，TUN 入站必须排除。

---

## 2. 总体架构

```
                      用户态 (sing-box)
  ┌──────────────────────────────────────────────────────────────┐
  │ inbound(ebpf/redirect/tproxy) → route → outbound             │
  │                                   │                          │
  │                    ┌──────────────┴───────────────┐          │
  │                    │ ebpf out 协调层               │          │
  │                    │ protocol/ebpf/outbound.go     │          │
  │                    │  ├─ Splicer  (模块 B)         │          │
  │                    │  ├─ VerdictWriter (模块 A)    │          │
  │                    │  └─ StatsPoller               │          │
  │                    └──────────────┬───────────────┘          │
  └───────────────────────────────────┼──────────────────────────┘
                                      │ bpf(2) map ops
  ┌───────────────────────────────────┼──────────────────────────┐
  │ 内核                               ▼                          │
  │  sb_splice_socks (SOCKHASH) ← sk_skb/stream_parser+verdict   │  模块 B
  │  sb_splice_peer  (HASH)                                      │
  │  sb_splice_bytes (PERCPU_HASH)                               │
  │  sb_splice_events(RINGBUF)  ← sock_ops/state_cb              │
  │                                                              │
  │  sb_out_verdict  (LRU_HASH) ← cgroup/connect4|6 查询          │  模块 A
  │                             ← tc/ingress 查询                 │
  └──────────────────────────────────────────────────────────────┘
```

### 2.1 文件布局（新增）

```
common/ebpf/
  outbound.go               // 出站后端 cgo 入口（对称 backend.go）
  outbound_nocgo.go         // 无 cgo 桩（对称 backend_nocgo.go）
  outbound_stub.go          // 非 linux/android 桩
  splice.go                 // Splice 配对/拆对/统计 的 Go API
  splice_test.go
  verdict.go                // 模块 A：verdict 编译 + 增量更新（对称 policy.go）
  verdict_test.go
  outbound_abi.go           // 出站 ABI 镜像（对称 abi.go）
  outbound_abi_test.go
  outbound_integration_test.go
  cgo_splice.c              // 3 行 #include，cgo 边界（对称 cgo_shared_network.c）
  native/
    singbox_ebpf_out.h      // 出站私有 ABI（对称 singbox_ebpf.h）
    splice.bpf.c            // clang -target bpfel 编译
    splice.bpf.o            // 生成物，.gitignore
    splice_runtime.c        // 建 map / 加载 / attach / 清理
    object_loader.c         // 由 shared_network_loader.c 泛化而来（共用）

protocol/ebpf/
  outbound.go               // 协调层 + 生命周期
  outbound_test.go
  splice_bridge.go          // 与 route/outbound 的粘合：判定可 splice、接管 fd、回退
  splice_bridge_test.go
  outbound_stats.go
  outbound_integration_test.go

option/ebpf.go              // 追加 EBPFOutboundOptions
include/ebpf.go             // 追加注册
include/ebpf_stub.go        // 追加"未编入本构建"的错误桩
```

### 2.2 形态选择：**不要注册成新的 outbound type**

不要做 `"type": "ebpf-out"`。出站类型必须承载真实协议（direct/shadowsocks/...），再包一层会破坏 `detour`、`urltest`、`ConnectionTracker` 与 clash-api。

正确形态：**在现有 `ebpf` 入站的配置块下增加 `outbound_offload` 子对象**，由入站实例持有出站后端。理由：
- 生命周期天然对齐（后端、cgroup、防环 cookie map 都归入站）；
- splice 需要 inbound socket 与 outbound socket 成对，协调层必须同时看到两端；
- 用户心智一致：eBPF 数据面是"一个开关"，不是两个互不相干的组件。

若后续要支持"非 ebpf 入站也能 splice"，再把后端提升为 `service`（`adapter.Service` + `service.FromContext`），配置改成顶层 `experimental.ebpf`。P0 不做，但**接口从第一天就按 service 化设计**（`Splicer` 不引用 `*Inbound`，只依赖 logger + 后端）。

---

## 3. 模块 B：sockmap splice（P0）

### 3.1 内核机制与选型

- **不用 `sk_msg`**。`sk_msg`/`bpf_msg_redirect_hash` 拦截的是本地进程 `sendmsg` 的**发送路径**，用于 sidecar；我们要转发的是"从远端 A 收到、转给远端 B"，属于**接收路径**。
- **用 `BPF_PROG_TYPE_SK_SKB`**：`BPF_SK_SKB_STREAM_PARSER` + `BPF_SK_SKB_STREAM_VERDICT`，verdict 里调用 `bpf_sk_redirect_hash(skb, &sb_splice_socks, &peer_key, 0)`，把 skb **从对端 socket 发到网络**（`tcp_bpf_sendmsg_redir`）。**禁止** `BPF_F_INGRESS`：那会把 skb 塞进对端接收队列（sidecar 模型），代理用户态已不读 → 连接卡死。
- parser 程序返回 `skb->len`（整段即一条消息，我们不做 L7 分帧）。
- attach 目标是**map fd**，不是 cgroup fd：`BPF_PROG_ATTACH{ target_fd = sockhash_fd, attach_bpf_fd = prog_fd, attach_type = BPF_SK_SKB_STREAM_* }`。
  → `sb_ebpf_attach_prog()`（`singbox_ebpf.h:188`）的第一个参数语义要从 "cgroup_fd" 泛化为 "target_fd"，函数体不用改。
- 内核门槛：`BPF_MAP_TYPE_SOCKHASH` + `bpf_sk_redirect_hash` 自主线 4.18/4.20；需要 `CONFIG_BPF_SYSCALL` + `CONFIG_NET_SOCK_MSG`（`CONFIG_BPF_STREAM_PARSER`）。5.13+ 可用 verdict-only（`BPF_SK_SKB_VERDICT`）省掉 parser，作为可选优化，不作基线。

**实现前必须先做 spike（半天量级），把以下三件事用真实内核日志确认，不要靠推断**：
1. `struct __sk_buff` 在 SK_SKB 上下文里 `remote_port` / `local_port` 的字节序（历史 quirk：`remote_port` 网络序放在 u32 高 16 位，`local_port` 主机序）。这是此类程序的头号 bug 来源。
2. 把一个 **ESTABLISHED** TCP socket 通过 `BPF_MAP_UPDATE_ELEM`（value = fd）加入 SOCKHASH 是否成功；非 ESTABLISHED 与已挂 ULP（kTLS）的 socket 预期失败（`EOPNOTSUPP`/`EINVAL`）。
3. socket 进入 sockmap 后，用户态 `epoll` 对该 fd 是否仍能收到 `EPOLLRDHUP` / `EPOLLERR` / `EPOLLHUP`。**这决定 3.5 节的关闭方案能不能落地**；若不能，必须走 `sock_ops` + ringbuf 方案。

### 3.2 map 与程序清单

| 名称 | 类型 | key | value | max_entries | 说明 |
|---|---|---|---|---|---|
| `sb_splice_socks` | `SOCKHASH` | `struct sb_splice_key`(36B) | fd（内核存 sock） | 65536 | 两端 socket 都注册在此；也是 attach 目标 |
| `sb_splice_peer` | `LRU_HASH` | `sb_splice_key` | `sb_splice_key` | 65536 | 双向各一条：A→B、B→A；满表 LRU 淘汰防撑死 |
| `sb_splice_bytes` | `PERCPU_HASH` | `sb_splice_key` | `u64` | 65536 | verdict 里累加 `skb->len`，供流量统计 |
| `sb_splice_stats` | `ARRAY` | `u32` | `u64` | `SB_SPLICE_STAT_COUNT` | 全局计数器 |
| `sb_splice_control` | `ARRAY` | `u32`(0) | `struct sb_splice_control` | 1 | `enabled`、`flags`（是否计数、是否 verdict-only） |
| `sb_splice_events` | `RINGBUF` | — | `struct sb_splice_event` | 256KiB | 仅 `sock_ops` 方案启用（3.5 节） |

程序：

| section | 类型 | attach | 作用 |
|---|---|---|---|
| `sk_skb/stream_parser` | `SK_SKB` | `BPF_SK_SKB_STREAM_PARSER`（target=`sb_splice_socks`） | `return skb->len` |
| `sk_skb/stream_verdict` | `SK_SKB` | `BPF_SK_SKB_STREAM_VERDICT` | 建 key → 查 `sb_splice_peer` → 累加 `sb_splice_bytes` → `bpf_sk_redirect_hash(..., 0)`；查不到返回 `SK_PASS`（**必须 PASS 不能 DROP**，否则拆对瞬间丢数据） |
| `sockops/state_cb` | `SOCK_OPS` | `BPF_CGROUP_SOCK_OPS` | 可选：状态迁移事件写 ringbuf |

### 3.3 ABI（`native/singbox_ebpf_out.h`）

沿用现有风格：全部定长、显式 `reserved`、`_Static_assert` 锁尺寸。

```c
#define SB_SPLICE_MAX_ENTRIES 65536U

enum sb_splice_stat_index {
    SB_SPLICE_STAT_PAIRS_CREATED = 0,
    SB_SPLICE_STAT_PAIRS_RELEASED,
    SB_SPLICE_STAT_REDIRECTS,
    SB_SPLICE_STAT_REDIRECT_FAILURES,
    SB_SPLICE_STAT_PEER_MISSES,
    SB_SPLICE_STAT_PASSTHROUGH,
    SB_SPLICE_STAT_COUNT,
};

struct sb_splice_key {
    uint8_t  family;        /* 2 / 10 */
    uint8_t  protocol;      /* 6 */
    uint16_t local_port;    /* 主机序，spike 确认 */
    uint16_t remote_port;   /* 主机序，spike 确认 */
    uint16_t reserved;
    uint8_t  local_addr[16];
    uint8_t  remote_addr[16];
};      /* 36 */

struct sb_splice_control {
    uint32_t enabled;
    uint32_t flags;         /* bit0 计数 bit1 verdict-only */
};      /* 8 */

struct sb_splice_runtime {
    int sock_map_fd;
    int peer_map_fd;
    int bytes_map_fd;
    int stats_map_fd;
    int control_map_fd;
    int events_map_fd;
    int parser_prog_fd;
    int verdict_prog_fd;
    int sockops_prog_fd;
    uint32_t attached_programs;
};

int sb_ebpf_splice_prepare(const uint8_t *object, size_t object_size,
                           uint32_t max_entries, bool enable_accounting,
                           struct sb_splice_runtime *runtime);
int sb_ebpf_splice_attach(struct sb_splice_runtime *runtime);
int sb_ebpf_splice_close(struct sb_splice_runtime *runtime);
```

Go 侧 `outbound_abi.go` 镜像该结构，并像 `abi_test.go` 那样加 `unsafe.Sizeof` 断言。

### 3.4 Go API（`common/ebpf/splice.go`）

```go
type SpliceBackend struct{ /* 同 Backend 的 access sync.RWMutex + runtime 指针模式 */ }

func PrepareSplice(maxEntries uint32, accounting bool) (*SpliceBackend, error)
func (b *SpliceBackend) Attach() error
func (b *SpliceBackend) Close() error
func (b *SpliceBackend) IsClosed() bool

// Pair 把两个已建立的 TCP socket 对拼。失败时保证不留半状态。
func (b *SpliceBackend) Pair(left, right syscall.RawConn) (*SplicePair, error)

type SplicePair struct{ /* 两端 key */ }
func (p *SplicePair) Release() error          // 幂等；从 peer/socks/bytes map 删除
func (p *SplicePair) Bytes() (up, down uint64, err error)

func (b *SpliceBackend) RuntimeStats() (SpliceStats, error)
```

`Pair()` 的顺序必须是：**先写 `sb_splice_peer` 两条，再把两个 socket 写入 `sb_splice_socks`**。反过来会出现"socket 已在 sockmap、peer 还没写"的窗口，verdict 走 `SK_PASS` 到用户态，而用户态此时已经不再 read → 数据卡住。任一步失败按逆序回滚（照 `backend.go:571 rollbackBypassCIDRPolicyMap` 的写法）。

### 3.5 生命周期与关闭（本模块最难的一块）

`sk_skb` 只搬数据，**不传递 FIN / RST 语义**。方案：

- **首选（先验证）**：两端 fd 由协调层持有，注册进一个 `epoll`，只关心 `EPOLLRDHUP|EPOLLERR|EPOLLHUP`。任一端触发 → `Release()` 拆对 → 关闭两端。前提是 3.1 spike 第 3 条成立。
- **备选**：加载 `sock_ops` 程序，订阅 `BPF_SOCK_OPS_STATE_CB_FLAG`，状态进入 `TCP_CLOSE_WAIT/FIN_WAIT/CLOSE` 时往 `sb_splice_events` ringbuf 投事件，Go 侧 reader goroutine 消费后拆对。代价是需要 cgroup attach（可复用入站的 cgroup fd）。
- **兜底（必须实现，不管上面哪个成立）**：`SplicePair` 带 idle 看门狗——若 `Bytes()` 在 `2 × UDPTimeout`（或独立 `splice_idle_timeout`）内无增长且两端均无 epoll 事件，强制拆对并关闭，避免 map 泄漏。map 占用要进 `RuntimeStats`，跑 soak 时观察是否回落（沿用 README 里已有的 Android soak 判据）。
- **半关闭**：不支持"一端 FIN 后另一端继续发"。这是可接受的退化（HTTP/1.1 半关闭上传、某些 gRPC 场景会受影响），必须在文档里写明，并提供 `splice.half_close: passthrough` 逃生开关（命中即拆对回落用户态，不是无损，但比挂死好）。

### 3.6 接入点：什么连接可以 splice

splice 的硬前提：**两端都是 TCP socket，且用户态在握手之后是纯字节搬运（无加密、无分帧、无填充）**。

| 出站 | 可否 splice | 原因 |
|---|---|---|
| `direct` | ✅ | 建连后纯中继 |
| `socks`（TCP，无 TLS） | ✅ | CONNECT 握手完成后无帧 |
| `http`（CONNECT，无 TLS） | ✅ | 200 之后无帧 |
| `redirect` / `tproxy` 侧回程 | ✅ | 同 direct |
| `shadowsocks` / `vmess` / `vless`(非 XTLS-splice) / `trojan` / `anytls` / `snell` / `hysteria*` / `tuic` / `ssh` / `wireguard` / `tailscale` | ❌ | 逐写加密或有帧头 |
| 任何开启 `multiplex` / TLS / uTLS / v2ray-transport 的出站 | ❌ | 同上 |
| UDP 全部 | ❌（P0） | 见 3.7 |
| TUN 入站来的连接 | ❌ | 入站侧不是真 socket |

实现方式（**不要用类型名字符串判断**）：在 `adapter` 加一个可选接口，由出站自己声明能力：

```go
// adapter/outbound.go
type SpliceCapableConn interface {
    // SpliceReady 在协议握手完成、且用户态缓冲已排空后返回底层 TCP 连接。
    // 返回 nil 表示本连接不可 splice。
    SpliceReady() *net.TCPConn
}
```

P0 只让 `protocol/direct` 实现它（`direct.Outbound.DialContext` 返回的 conn 包一层）。`socks`/`http` 放 P1。协调层的判定链：

1. 入站是否声明支持（`ebpf` / `redirect` / `tproxy`；TUN 排除）；
2. 双方都是 TCP 且 `SpliceReady() != nil`；
3. 该连接**没有**待处理的 sniff（sniff 必须在 splice 之前完成，因为 splice 后用户态再也看不到字节）；
4. 该连接没挂 `ConnectionTracker` 之外的字节级中间件（限速、`proxy_protocol` 写入完成后才允许）；
5. **已经读进用户态的缓冲必须先写出**——`buf.Buffer` 里的残留字节要在 `Pair()` 之前 flush 到对端，否则乱序。这是第二号 bug 来源，必须有单测覆盖。

任一条不满足 → 走现有 `bufio.CopyConn`，只记一条 debug 日志。**splice 永远是优化，不是功能**；`Pair()` 返回错误时也必须无损回落。

### 3.7 UDP

`sk_skb` 的 stream verdict 面向流式 socket。主线 5.8 起 sockmap 支持 UDP socket，但 `SK_SKB` verdict 对 UDP 的支持不完整、跨版本差异大。**P0 明确不做 UDP splice**；UDP 的收益应该走模块 A（直连 offload），不是 splice。若后续要做，先单独 spike，别混在 P0 里。

---

## 4. 模块 A：flow verdict offload（P1）

### 4.1 数据结构

```c
#define SB_OUT_VERDICT_DIRECT 1U
#define SB_OUT_VERDICT_PROXY  2U

struct sb_out_verdict_key {
    uint8_t  family;
    uint8_t  protocol;
    uint16_t port;          /* 0 = 通配该地址所有端口 */
    uint8_t  addr[16];
    uint32_t reserved;
};      /* 24 */

struct sb_out_verdict_value {
    uint8_t  verdict;
    uint8_t  reserved[3];
    uint32_t generation;    /* 与 control.generation 不等则视为失效 */
    uint64_t expire_ns;     /* bpf_ktime_get_ns() 基准 */
};      /* 16 */
```

map：`sb_out_verdict`，`LRU_HASH`，65536。用 LRU 而不是 HASH，是为了让容量上限退化成"命中率下降"而不是"更新失败"。

### 4.2 内核侧查询点

1. **本机路径**：`connect_prog.c` 新增 `emit_flow_verdict_bypass()`，插在 socket cookie 防环之后、CIDR bypass 之前（即 `emit_socket_cookie_bypass()`（`:703`）与 `emit_ipv4_cidr_bypass()`（`:763`）之间）。命中 `DIRECT` 且未过期 → 不改写地址直接返回 1，流量原样直连。
2. **共享网络路径**：`shared_network.bpf.c` 的 ingress 在现有 `shared_bypass_ipv4/6` 查询之后追加一次 `sb_out_verdict` 查询，命中 DIRECT → `TC_ACT_OK`，交还内核转发。

过期判断放内核（比较 `bpf_ktime_get_ns()`）+ 用户态定期清理，双保险。`generation` 用于 reload：配置变更时 Go 侧把 `control.generation++`，全表一次性失效，不需要遍历删除。

### 4.3 谁来写 verdict —— 三种模式，默认关

```
outbound_offload.verdict.mode:  off | learn | dns
```

- **`off`（默认）**：不启用。行为与今天完全一致。
- **`learn`**：连接**结束后**回写。第一条连接照常进用户态、照常经过完整路由与 sniff；路由结论若是"direct 且该结论与 sniff 无关"，则写入 `(dst_ip, dst_port) → DIRECT`，TTL 默认 300s。后续同目标连接不进用户态。
- **`dns`**：在 DNS 应答回填时，对 `(domain, 解析出的 IP)` 做一次路由预匹配，结论 direct 则写入。这是 dae 的收益模型（第一条连接也不进用户态），但需要 router 暴露一个"仅用 IP/域名/端口维度做干跑匹配"的 API，且必须能报告"本次匹配是否触及不可提前判定的维度"。

### 4.4 安全门（不可省）

写入 verdict 前必须全部成立，否则跳过（记 debug 计数，不报错）：

1. 命中的路由规则集合**不包含**任何依赖以下维度的规则：sniff 出来的 domain/protocol/client、`user`/`auth_user`、`process_name`/`package_name`、`rule_set` 中的 domain 规则（除非该规则已用 IP 表达）。
2. 目标出站是 direct 语义：实现 `dialer.DirectDialer`、无 `detour`、无 `proxy_protocol`、无域名策略改写。
3. 该目标不在 DNS 劫持范围（端口 53 一律不 offload，避免与 `dns_mode: hijack` 打架）。
4. 入站未开启 `sniff`（或开启但用户显式 `verdict.allow_with_sniff: true` 承担风险）。

**判据得不到就不写**，这条比任何性能收益都重要：错误的 direct offload = 静默泄漏，用户看不到日志、也无法从 clash-api 观察到（流量根本不进用户态）。因此还要求：

- verdict 表全量可通过 `experimental.debug` HTTP 端点导出（`key → verdict/ttl/来源`），便于现场排障；
- `learn` 模式下每次写入打 debug 日志（含来源规则 tag）。

### 4.5 失效

- TTL 到期；
- `generation++`（配置 reload）；
- `InterfaceUpdated()` 触发全表清空（沿用 `protocol/ebpf/inbound.go:646` 的钩子）；
- 出站健康检查失败/切换 → 清空该出站贡献的条目（需要在 value 里再存一个 `owner_hash`，或简单起见直接全清）。

---

## 5. 模块 C：出站侧 cgroup egress（P2）

范围克制，只做三件事：

1. **防环强化**：现在靠 `ProtectFunc` 往 cookie map 写（`backend.go:605`）。加一个 `cgroup/sock_create` 或复用 `connect4/6` 的早期分支，对"由 sing-box 自己发起、且目标是自身 listener 端口"的情况直接放行 + 计数，避免依赖调用方记得 protect。
2. **出站 mark / 绑定下沉**：多 WAN 场景把 `routing_mark`/`bind_interface` 写进 map，由 `cgroup/sock_create` 统一打 `SO_MARK`，替代 Go 侧逐 dialer 设置。收益是"新加的 dialer 忘记设置"这类 bug 消失。
3. **UDP direct offload**：TC egress + 一张 conntrack map，让被判 DIRECT 的 UDP 流在内核完成往返。这块复杂度接近重写 shared_network 的一半，**建议单独立项，不要塞进本框架的 P2**。

---

## 6. 配置 schema（`option/ebpf.go` 追加）

```go
type EBPFInboundOptions struct {
    // ... 现有字段不变
    OutboundOffload EBPFOutboundOffloadOptions `json:"outbound_offload,omitempty"`
}

type EBPFOutboundOffloadOptions struct {
    Splice  EBPFSpliceOptions  `json:"splice,omitempty"`
    Verdict EBPFVerdictOptions `json:"verdict,omitempty"`
}

type EBPFSpliceOptions struct {
    Enabled     bool   `json:"enabled,omitempty"`
    MaxPairs    uint32 `json:"max_pairs,omitempty"`                              // 0 → 65536
    Accounting  *bool  `json:"accounting,omitempty"`                             // 默认 true
    HalfClose   string `json:"half_close,omitempty" enum:"close,passthrough"`    // 默认 close
    IdleTimeout badoption.Duration `json:"idle_timeout,omitempty"`               // 0 → 2×UDPTimeout
}

type EBPFVerdictOptions struct {
    Mode           string             `json:"mode,omitempty" enum:"off,learn,dns"` // 默认 off
    TTL            badoption.Duration `json:"ttl,omitempty"`                       // 0 → 5m
    MaxEntries     uint32             `json:"max_entries,omitempty"`               // 0 → 65536
    AllowWithSniff bool               `json:"allow_with_sniff,omitempty"`          // 默认 false
}
```

最小启用示例：

```json
{
  "type": "ebpf",
  "network": ["tcp", "udp"],
  "outbound_offload": {
    "splice": { "enabled": true }
  }
}
```

`docs/schema.json` 与 `docs/configuration/inbound/ebpf.md` / `.zh.md` 同步更新；`docs/manual/misc/ebpf-inbound-comparison.zh.md` 的"直连流量/代理流量"两行要按实际落地情况改写。

---

## 7. 测试与验收

沿用 `common/ebpf/README.md` 已有的约定，新增：

```sh
# 单元（三种模式都要过，和现有约定一致）
CGO_ENABLED=1 go test -tags with_ebpf ./common/ebpf ./protocol/ebpf ./include
CGO_ENABLED=0 go test -tags with_ebpf ./common/ebpf ./protocol/ebpf ./include
CGO_ENABLED=1 go test -race -tags with_ebpf ./common/ebpf ./protocol/ebpf ./include

# Android 交叉编译（验证 NDK 头与 cgo 边界）
GOOS=android GOARCH=arm64 CGO_ENABLED=1 CC=$NDK/.../aarch64-linux-android33-clang \
  go test -c -tags with_ebpf -o /tmp/sb-ebpf-out-android.test ./protocol/ebpf

# 加载集成（只 verifier 加载，不 attach）
sudo -E SING_BOX_EBPF_OUT_INTEGRATION=1 \
  go test -count=1 -run TestSpliceProgramLoadIntegration -tags with_ebpf ./common/ebpf

# 数据面集成（netns + veth，回环两条 TCP 走 splice）
sudo -E SING_BOX_EBPF_SPLICE_INTEGRATION=1 \
  go test -count=1 -run TestSpliceDataPathIntegration -tags with_ebpf ./protocol/ebpf
```

### 验收标准（每条都要有证据，不接受"应该没问题"）

**模块 B**
1. 1MiB / 100MiB 双向传输字节完全一致（含随机分片、`TCP_NODELAY` 开关两种）；
2. `sb_splice_bytes` 统计与实际字节数误差 0；
3. 任一端 `close()` / `RST` 后另一端在 1s 内收到关闭，且 `sb_splice_socks`/`peer`/`bytes` 三张表条目归零；
4. `Pair()` 中途注入失败（mock map 更新错误）→ 连接仍然正常传输（回落用户态），无泄漏条目；
5. splice 前用户态缓冲有残留字节的场景，字节序完全正确（专门单测）；
6. 2 小时 soak：1000 条短连接 + 10 条长连接反复起停，三张表占用回到基线，`REDIRECT_FAILURES` 与 `PEER_MISSES` 为 0；
7. `iperf3` 对比：splice 开/关的吞吐与 CPU（`pidstat` 采样）写进结果文档 —— **如果吞吐没有可测量的提升，这个模块就该被否决，不要为了用 eBPF 而用**。

**模块 A**
8. `learn` 模式：第一条连接走用户态且日志可见，第二条同目标连接**不出现**在 clash-api 连接列表，同时 `tcpdump` 证明流量确实直连；
9. 安全门测试：构造"依赖 sniff 才能判定"的配置，确认**不写入** verdict（这是回归测试重点，必须有）；
10. `generation++` 后所有旧条目立即失效；
11. verdict 表可通过 debug 端点导出。

---

## 8. 风险与限制（提前写清，避免返工）

| 风险 | 影响 | 处置 |
|---|---|---|
| sockmap 与 kTLS/ULP 冲突 | `Pair()` 失败 | 只对 `SpliceReady()` 返回裸 TCP 的连接尝试；失败即回落 |
| 半关闭语义丢失 | 少数应用异常 | 文档写明 + `half_close: passthrough` 逃生开关 |
| splice 后用户态失去字节可见性 | sniff、限速、字节级中间件失效 | 判定链第 3/4 条硬性排除；sniff 必须先完成 |
| 流量统计需从 map 拉取 | clash-api 数字延迟 | `PERCPU_HASH` + 1s 轮询喂给 `ConnectionTracker`；轮询失败时该连接标记为"统计不可用"而不是显示 0 |
| verdict offload 静默错误分流 | **可能造成隐私/合规事故** | 默认 off、显式 opt-in、安全门、可导出表、逐条 debug 日志 |
| 自定义加载器需支持新 prog/map 类型 | 加载失败 | 先泛化 `object_loader.c` 并补加载集成测试，再写业务逻辑 |
| Android 厂商内核缺 `CONFIG_NET_SOCK_MSG` | 功能不可用 | 启动时能力探测（建一张 SOCKHASH 试 attach），失败降级为纯用户态并 warn，不阻塞入站启动 —— 与 `checkKernelCapabilities()`（`backend.go:308`）同风格 |
| verifier 在旧内核拒绝 | 加载失败 | 程序保持极简（parser < 10 条指令，verdict < 60 条），不用 `bpf_loop`、不依赖 BTF/CO-RE（与现有实现一致） |
| 新增两个内核对象 + 一套 cgo 边界的维护成本 | 长期 | 复用现有 Makefile `check` 机制保证生成物可复现；`.o` 继续不入 git |

---

## 9. 交给实现方的任务清单

按顺序执行，每个任务独立可验证、可回滚。**任务 0 的结论若为负，后续设计需要调整，不要跳过。**

| # | 任务 | 改动 | 完成判据 |
|---|---|---|---|
| **0** | **能力 spike** | 独立小程序（不进主仓） | 3.1 节三个问题各有一份内核实测日志；产出 `docs/ebpf-splice-spike-<date>.md` |
| 1 | 泛化 ELF 加载器 | `shared_network_loader.c` → `object_loader.c`（加 `prog_type`/`attach_type`/map fd 表参数）；`shared_network_runtime.c` 适配 | 现有 shared_network 全部测试不回归 |
| 2 | Makefile 支持多对象 | `common/ebpf/Makefile` | `make ebpf_generate` / `ebpf_check` 对两个 `.c` 都生效 |
| 3 | 内核对象 | `native/splice.bpf.c` + `native/singbox_ebpf_out.h` | clang 编译通过；verifier 在目标内核上加载通过 |
| 4 | 运行时 C 层 | `native/splice_runtime.c` + `cgo_splice.c` | `TestSpliceProgramLoadIntegration` 通过 |
| 5 | Go 后端 | `common/ebpf/splice.go` / `outbound.go` / `outbound_nocgo.go` / `outbound_stub.go` / `outbound_abi.go` + 单测 | 三种 go test 模式 + Android 交叉编译通过 |
| 6 | 能力接口 | `adapter` 加 `SpliceCapableConn`；`protocol/direct` 实现 | 单测覆盖"不可 splice 时回落" |
| 7 | 协调层 | `protocol/ebpf/outbound.go` + `splice_bridge.go`；接入 `Inbound.Start/Close` | 验收 1–6 全过 |
| 8 | 统计 | `protocol/ebpf/outbound_stats.go`；接 `ConnectionTracker` / clash-api | 验收 2 通过；周期性 metrics 日志格式与现有 `eBPF runtime metrics` 一致 |
| 9 | 配置与文档 | `option/ebpf.go`、`docs/schema.json`、`docs/configuration/inbound/ebpf*.md`、对比文档更新 | schema 校验通过 |
| 10 | 性能报告 | 新增 `docs/ebpf-splice-benchmark-<date>.md` | 验收 7；**结论为"无提升"时如实写并暂停 P1** |
| 11 | 模块 A（P1） | 见第 4 节 | 验收 8–11，尤其第 9 条 |

---

## 10. 一句话总结给实现方

先把"进了用户态也别拷两遍"（模块 B / sockmap splice）做扎实，它语义无损、可逐连接回退、收益可测量；再考虑"根本别进用户态"（模块 A / verdict offload），它才是 dae 的性能模型，但要用默认关闭 + 安全门 + 可导出表把静默错误分流的风险按住。任务 0 的三个内核实测不做完，不要开始写业务代码。
