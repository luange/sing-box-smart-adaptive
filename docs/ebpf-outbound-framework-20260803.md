# eBPF Outbound 数据面框架

日期：2026-08-03  
源码基线：`work/a51-beta4-adaptive`（with_ebpf）  
关联：

- 入站对比：`work/a51-beta4-adaptive/docs/manual/misc/ebpf-inbound-comparison.zh.md`
- 入站 PBR 重设计：`Documents/Codex/2026-07-17/new-chat-3/outputs/ebpf-dataplane-redesign-20260803.md`
- 生产热路径：VM115 token 双 hook（ingress+egress rewrite）已验证；本框架**不替代**该路径

Claude session `0328c404` 已完成源码勘察与思路收敛，本文把其未落盘的设计写成可实施框架，供 Grok/Codex 按批次实现。

---

## 0. 一句话结论

**eBPF outbound 不是新的代理协议出站，也不是 TC egress 令牌回写。**  
它是：在 **sing-box 用户态完成路由决策之后**，把「直连绕过」和「TCP 明文中继」两类路径下沉到内核，减少 userspace `bufio.Copy` 与重复拦截成本。

| 概念 | 是什么 | 不是什么 |
|---|---|---|
| 入站 `type: ebpf` | 透明捕获 → listener | 出站协议 |
| TC egress（token） | 入站数据面完整：应答五元组还原 | config `outbounds[]` |
| **本框架 eBPF-out** | 路由后的 offload / verdict | `{"type":"ebpf"}` 放进 outbounds |

现有文档已点明痛点：未下沉的 `direct` 仍走用户态中继；dae 的优势正是「分流=direct 时内核放行」。本框架补这一侧，**不把完整规则引擎搬进 eBPF**。

---

## 1. 目标与非目标

### 1.1 目标

1. **P0 Sockmap splice**：TCP 两端 socket 均已建立且后续仅为双向明文拷贝时，用 `SOCKHASH` + `sk_msg`/`sk_skb` verdict 在内核完成转发，用户态只保留连接生命周期与计数。
2. **P1 Flow verdict cache**：用户态已判定 direct（或等价直连）后，把 5-tuple / cookie 写入内核 map，使 cgroup connect 与 `shared_network` TC **后续新建或同流** 可 bypass，避免「direct 仍进 sing-box 再 dial」。
3. **P1.5 DNS prefill（可选）**：DNS 响应得到 A/AAAA 后，按路由结果预写 domain→verdict 或 IP→verdict，缩短首包仍被拦截的窗口。
4. **可观测**：独立 counters；失败一律 fail-open 回退 userspace 路径。
5. **与现有入站共存**：token / socket_assign 两种 `data_plane` 均可挂接；不强制改 115 生产 token 路径。

### 1.2 非目标（明确不做）

- 不在 eBPF 内实现 vmess/trojan/hysteria 等协议编解码。
- 不复制 dae 的完整 TC 分流语言（域名/MAC/进程规则全集）。
- 不把 `TypeEBPF` 注册成 outbound 路由目标（避免与 inbound 同名冲突、语义混乱）。
- 不替代 token 双 hook 的「应答还原」职责（那是入站 GW 完整性问题）。
- 第一版不做 UDP sockmap 中继（内核支持与路径差异大，见 P2）。
- 不在未过 gate 前在 115 生产默认开启；默认 canary：**116**。

---

## 2. 现状与挂钩点（源码事实）

### 2.1 入站 only

| 位置 | 现状 |
|---|---|
| `constant.TypeEBPF = "ebpf"` | 仅 inbound 语义（`ProxyDisplayName` / `Is*Inbound`） |
| `include/ebpf.go` | 只 `RegisterInbound` |
| `option/ebpf.go` | 只有 `EBPFInboundOptions` |
| `protocol/ebpf/*` | inbound + shared_network + route，无 outbound.go |
| `common/ebpf` | cgroup connect 程序手写指令；TC 对象 `shared_network.bpf.c`；已有 **SOCKMAP** 用于 `sk_assign` listener |

### 2.2 用户态中继热点

`route/conn.go` → `ConnectionManager.NewConnection`：

1. `DialSerialNetwork` / `DialContext` 建立 `remoteConn`
2. handshake / TLS fragment / spoof 包装
3. 两个 goroutine：`connectionCopy` → `bufio.CopyWithIncreateBuffer`

**P0 插入点**：步骤 2 成功、步骤 3 之前——若两端可 offload，则注册 sockmap 并 **不再** 起 copy goroutine；连接对象仍登记到 ConnectionManager，靠 epoll/关闭回调与 per-pair 计数收尾。

### 2.3 直连仍进用户态

`bypass_rule_set` / 内置私网等可在 **拦截前** 放行；  
规则命中 `direct` outbound 的流量仍是：捕获 → accept → route → dial direct → copy。  
P1 要补的是第二种。

### 2.4 已有 SOCKMAP 能力

`shared_network.bpf.c` 已用 `BPF_MAP_TYPE_SOCKMAP` + `bpf_sk_assign` 做 **listener 投递**（入站）。  
P0 的 sockmap 是 **已建立连接的 sk_msg 转发**，map 类型建议 **SOCKHASH**（key 可自定），程序类型不同，可复用 loader/map syscall 基础设施，**不要** 与 listener SOCKMAP 混用同一 map。

---

## 3. 总体架构

```text
                    ┌─────────────────────────────────────┐
                    │         sing-box 用户态              │
  client ──► eBPF-in │  accept → route/smart → dial out   │
                    │              │                      │
                    │    ┌─────────┴──────────┐           │
                    │    ▼                    ▼           │
                    │ verdict=DIRECT     明文 TCP 中继      │
                    │    │                    │           │
                    └───┬────────────────────┬────────────┘
                        │ write               │ pin pair
                        ▼                    ▼
              flow_verdict map      SOCKHASH + sk_msg prog
                        │                    │
              cgroup/TC bypass      kernel splice 双向
                        │                    │
                        ▼                    ▼
                   内核直连 L3           peer socket 收发
```

### 3.1 组件划分

| 组件 | 包路径（建议） | 职责 |
|---|---|---|
| 配置 | `option/ebpf.go` 扩展 | `EBPFOutboundOffloadOptions`（挂在 inbound 或 experimental） |
| 控制面 | `protocol/ebpf/offload.go` | 生命周期、与 Inbound/ConnectionManager 协作 |
| 后端 | `common/ebpf/outbound_backend.go` + `native/outbound_*.c` | map/prog load、pin socket、verdict update |
| BPF 对象 | `native/outbound_sockmap.bpf.c` → `.bpf.o` embed | sk_msg / 可选 sk_skb |
| 路由钩子 | `route/conn.go` + direct/route action | 调用 Offload API |
| DNS 钩子 | DNS router 响应路径（可选 P1.5） | prefill IP verdict |
| 指标 | `protocol/ebpf/runtime_stats.go` 扩展 | offload 专用计数 |

### 3.2 配置形态（推荐）

**不要** 新增 `"type": "ebpf"` outbound。  
推荐挂在 eBPF inbound 上（与 capture 同生命周期），或 `experimental`：

```json
{
  "type": "ebpf",
  "tag": "ebpf-in",
  "capture_local": false,
  "shared_network": {
    "enabled": true,
    "include_interface": ["pa-hk", "pa-us", "eth0"],
    "data_plane": "socket_assign"
  },
  "outbound_offload": {
    "enabled": true,
    "sockmap_tcp": true,
    "flow_verdict": true,
    "dns_prefill": false,
    "max_pairs": 65536,
    "verdict_ttl_ms": 300000,
    "fail_open": true
  }
}
```

说明：

- `enabled=false`（默认）：行为与今天完全一致。
- 仅 Linux/Android + `with_ebpf` + cgo；其它平台 option 可解析但 Start 时 no-op 或拒绝。
- 与 `data_plane=token|socket_assign` 正交：verdict bypass 写入点不同，offload API 统一。

### 3.3 为何不做独立 outbound type

1. 路由规则写 `outbound: ebpf-out` 无法表达「对任意上游协议做 splice」。
2. splice 发生在 **已选 outbound 并 dial 成功之后**，属于 ConnectionManager 能力。
3. verdict 是对 **direct 决策** 的副作用，不是新的 dial 实现。
4. 避免 `TypeEBPF` 同时表示 in/out 的配置与代码灾难。

若将来需要「显式开关某条路由启用 offload」，用 rule action 扩展或 metadata flag，而不是新 type。

---

## 4. P0：Sockmap TCP splice

### 4.1 适用条件（全部满足才 offload）

1. 网络为 TCP。
2. `conn` 与 `remoteConn` 底层均可拿到 **原始 `*os.File` / fd**（无尚未消费完的用户态缓冲，或缓冲可先 drain）。
3. 两侧都 **不是** 需要继续在用户态处理的包装层：
   - 禁止：仍需 TLS 终端、协议混淆、multiplex 流、packet-conn 适配、还要读首包 sniff 的路径。
   - 允许典型场景：
     - eBPF/TProxy/TUN 明文 accept + `direct` dial
     - eBPF accept + **已完成** 协议握手后的裸 TCP 中继（多数代理出站在 Dial 返回的已是「对节点的加密连接」，此时 splice 的是 **客户端明文 ↔ 节点 TLS/加密 socket**——**仅当** 应用层不再在中间插入代理协议帧时才成立）
4. **关键限制（第一版收紧）**：

   **仅 offload「两端都是透明/直连语义」的路径：**

   - inbound: ebpf / tproxy / tun / redirect 明文  
   - outbound: `direct`（或 bridge 等无应用层协议）

   加密代理（vmess 等）的 Dial 返回 socket 上跑的是代理协议，**不能** 把客户端 TLS 字节直接 sk_msg 到该 socket而不经协议封装。  
   → 第一版 **只做 direct（及纯透传）splice**，代理协议留 P3「协议后 splice」（需要协议实现暴露 inner plain conn，多数做不到）。

5. 无 `TLSFragment` / `TLSSpoof` 等仍要包装 remote 的 metadata。
6. 内核与 config 支持 sockmap；`UpdateSockmap` 成功。

不满足则完整走现有 `connectionCopy`。

### 4.2 内核对象

| 对象 | 类型 | 说明 |
|---|---|---|
| `sb_out_sockhash` | `BPF_MAP_TYPE_SOCKHASH` | key: `u64` pair_id 或 `{cookie_a,dir}`；value: sk |
| `sb_out_pair_meta` | `LRU_HASH` | pair_id → {bytes_tx, bytes_rx, flags, created_ns} |
| `sb_out_stats` | `ARRAY` | 全局计数 |
| prog `sb_out_sk_msg` | `BPF_PROG_TYPE_SK_MSG` attach `BPF_SK_MSG_VERDICT` | `bpf_msg_redirect_hash` 到 peer |
| 可选 prog `sb_out_sockops` | `BPF_PROG_TYPE_SOCK_OPS` | 状态观测；非必须 |

构建方式：

- **优先 clang → `outbound_sockmap.bpf.c` → bpfel `.o` → 扩展现有 ELF loader**（与 TC 相同路线）。  
- **不要** 在 `connect_prog.c` 里手搓 sk_msg 长程序。

内核要求（部署 gate）：

- `CONFIG_BPF_STREAM_PARSER`（若使用 stream parser attach）
- SOCKHASH + sk_msg redirect（主线约 4.20+；以目标机 verifier 实测为准）
- 5.13+ 可评估 verdict-only 路径；文档写清最低实测矩阵（PVE 6.x / 群辉 / OpenWrt）

### 4.3 用户态流程

```text
NewConnection 成功 dial 后:
  if !offload.Enabled || !offload.SockmapTCP: goto copy
  if !eligible(metadata, this, conn, remote): goto copy
  pairID = alloc()
  if err := backend.PinTCPPair(pairID, fdLocal, fdRemote); err != nil: goto copy
  registerConnTrack(pairID, conn, remote, onClose)  // 不启动 copy goroutine
  // 可选：设置 non-blocking 并由 backend 接管；fd 不可被 Go runtime 并发 Read
  waitClose(pairID) // epoll HUP / sockops / 对端 FIN
  backend.Unpin(pairID); onClose(); metrics++
```

**fd 所有权**：Pin 成功后 Go 侧必须停止对这两个 conn 的 Read/Write；Close 仍由用户态发起以触发内核拆对。推荐 `SyscallConn` + `SetNonblock` + 从 net.Conn 抽 fd 后用 `runtime.KeepAlive` 策略，或 `dup` 后把原 conn Close 交给 map（实现阶段选一种并写测试）。

### 4.4 计数与 Clash 流量

- BPF 侧 atomic add bytes；用户态定时 `Lookup` 刷新 `ConnectionManager` / clash traffic。
- 或接受「offload 连接只计连接数、不计精确字节」的第一版折中——**不推荐**；至少提供 pair_meta 字节。

### 4.5 失败与 reload

- pin 失败 → 立即 userspace copy（fail-open）。
- reload：先停新 offload，现有 pair 可保留到连接结束；prog 替换用原子替换 map fd / 新 generation。
- 进程退出：map 随 fd 关闭，连接应回到栈行为或断开（需测）。

---

## 5. P1：Flow verdict cache（direct bypass）

### 5.1 语义

```text
verdict = BYPASS_KERNEL_DIRECT | INTERCEPT_DEFAULT | (预留 BLOCK)
```

- `BYPASS`：cgroup connect4/6 与 shared_network TC 对该流（或目标）直接放行，不改写、不 sk_assign。
- 默认未命中：保持现有拦截。

### 5.2 谁写入

| 写入者 | 时机 | key 建议 |
|---|---|---|
| Route 命中 final outbound type=direct | L4 连接建立前（若已有 destination IP） | 5-tuple 或 dst IP+port+proto |
| ConnectionManager direct dial 成功 | 确认直连可用后 | 同上 + socket cookie |
| DNS prefill（P1.5） | DNS 应答 + 规则预匹配 direct | dst IP（短 TTL） |
| bypass_rule_set 已有 | 已在 map，不必重复 | — |

**注意**：smart/adaptive 可能先探测再变卦。写入策略：

- 仅在 **最终 outbound 确定为 direct 且不会再 retry 换节点** 后写长期 verdict；
- 或写短 TTL（如 1–5s）仅加速同 dst 连发；
- interrupt/retry 路径禁止把「曾 direct」写成永久 BYPASS。

### 5.3 与 data_plane 的衔接

| data_plane | BYPASS 行为 |
|---|---|
| token | TC ingress 查 verdict map，命中则不 token 化；egress 无条目则本就 noop |
| socket_assign | TC 不 mark / 不写 flow map；sk_lookup 无条目则不 assign |
| cgroup local capture | connect 程序查 cookie/dst，命中则 `return 1` 不改写 |

### 5.4 与 redesign 文档关系

`ebpf-dataplane-redesign` 主张 socket_assign **不要 egress rewrite**——与 P1 一致。  
P1 **不是** 恢复 token egress；只是「决策后少进用户态」。  
115 若继续 token，P1 仍可只开 cgroup/TC ingress 侧 bypass。

### 5.5 风险

- **错误 BYPASS = 泄漏**（该代理却直连）。必须：规则变更/reload 清空或 generation bump；默认 fail-open 指 offload 失败，**不是** 指「不确定时 BYPASS」。
- FakeIP：verdict key 必须用 **路由后真实 IP** 或 fakeip 映射一致的 key，禁止混用。
- 网关多客户端：key 应含 src（client）+ dst，不能只按 dst 全局 BYPASS。

---

## 6. P2：UDP（后续）

| 方向 | 说明 |
|---|---|
| verdict bypass | 与 TCP 类似，TC/cgroup 对 UDP 放行；优先做 |
| sockmap UDP | 较新内核；与现有 udpnat/token 生命周期缠在一起，**第二阶段** |
| QUIC/443 | 现有 `drop_udp_443` 策略保留；offload 不默认打开 443/udp |

---

## 7. API 草图（Go）

```go
// common/ebpf/outbound_offload.go
type OutboundOffload interface {
    Start() error
    Close() error

    // P0
    TryPinTCPPair(local, remote syscall.Conn, meta PairMeta) (pairID uint64, ok bool, err error)
    UnpinPair(pairID uint64) error
    PairStats(pairID uint64) (tx, rx uint64, err error)

    // P1
    SetFlowVerdict(key FlowKey, v Verdict, ttl time.Duration) error
    DeleteFlowVerdict(key FlowKey) error
    BumpGeneration() // reload

    RuntimeStats() OutboundOffloadStats
}

type Verdict uint8
const (
    VerdictDefault Verdict = 0
    VerdictBypassDirect Verdict = 1
)
```

`protocol/ebpf.Inbound` 在 `Start` 时若 `outbound_offload.enabled`，创建并挂到 `service.Context` 或 `ConnectionManager` 可取的单例。

`route/conn.go`：

```go
if off, ok := ebpf.OutboundOffloadFromContext(ctx); ok {
    if id, pinned, _ := off.TryPinTCPPair(...); pinned {
        m.trackOffloaded(ctx, id, conn, remoteConn, onClose)
        return
    }
}
// existing copy path
```

direct 命中时（route 最终 action）：

```go
off.SetFlowVerdict(flowKeyFrom(metadata), VerdictBypassDirect, ttl)
```

---

## 8. 源码落地批次（PR 计划）

### PR-A：骨架（可编译、默认关闭）

- [ ] `option.EBPFOutboundOffloadOptions` + JSON 测试  
- [ ] `include` / stub 无 cgo  
- [ ] `common/ebpf/outbound_offload_{linux,stub}.go` 空实现  
- [ ] `protocol/ebpf/offload.go` 挂生命周期  
- [ ] 文档本文件入库  

### PR-B：P0 sockmap

- [ ] `native/outbound_sockmap.bpf.c` + make `ebpf_generate`  
- [ ] loader 支持 `BPF_PROG_TYPE_SK_MSG` + SOCKHASH update  
- [ ] `TryPinTCPPair` + conn.go 钩子（feature flag）  
- [ ] netns 集成测试：iperf/dd 大流量，CPU 对比 userspace copy  
- [ ] 失败回退测试  

### PR-C：P1 verdict

- [ ] verdict map + connect_prog / shared_network.bpf 查询点  
- [ ] route/direct 写入 + generation  
- [ ] 泄漏测试：应代理域名不得因陈旧 verdict 直连  
- [ ] 116 canary 脚本与回滚  

### PR-D：P1.5 DNS prefill（可选）

- [ ] DNS 响应钩子  
- [ ] 短 TTL + FakeIP 单测  

### PR-E：可观测与生产开关

- [ ] stats 并入 `eBPF runtime metrics` 日志  
- [ ] 使用说明 / 参数说明  
- [ ] 默认仍 false；116 → 再评估 115  

---

## 9. 验收 Gates

### 9.1 功能

1. offload 关闭：与 baseline 行为 bit-identical（配置解析除外）。  
2. P0：direct TCP 大文件，pin 成功时无 userspace copy goroutine 热点；断开后无 fd/map 泄漏。  
3. P0 失败注入：强制 pin 失败 → 自动 copy，业务成功。  
4. P1：重复访问 direct IP，第二次起 cgroup/TC 计数显示 bypass↑、redirect 不增。  
5. P1 负例：proxy 域名永不进 bypass map。  
6. reload / SIGHUP：无黑洞；generation 后旧 bypass 失效。  

### 9.2 性能（116）

- direct 吞吐 ≥ userspace copy 的 1.0x（目标 ≥ 1.2x，CPU ≤ 0.7x）。  
- 与 VM107 tproxy 对比作参考，不作为硬门槛。  

### 9.3 安全

- 无 destination 明文进日志。  
- verdict 默认 deny-bypass（未显式写入则不 BYPASS）。  

---

## 10. 与 Claude 思路对齐说明

Claude 收敛的三点全部吸收，优先级微调如下：

| Claude | 本文 | 理由 |
|---|---|---|
| sockmap splice P0 | **仍为 P0** | 挂钩清晰、与 listener SOCKMAP 基建可复用、收益直观 |
| flow verdict P1 | **仍为 P1** | 对齐 dae 直连优势；但安全要求更高，需 generation |
| DNS prefill | P1.5 | 依赖稳定路由预判，放 verdict 之后 |
| UDP | P2 | 与 token/udpnat 耦合深 |
| clang 对象而非手写 sk_msg | **采纳** | connect_prog 手写已过重 |
| 不写独立 outbound.go 协议 | **采纳并强化** | 用 offload 子系统，避免 type 冲突 |

**未采纳**：把「eBPF outbound」做成与 shadowsocks 并列的 dial outbound。那会误导配置且无法覆盖 splice/verdict 真实挂钩点。

---

## 11. 实施时注意的张力

1. **115 token 双 hook 生产正确** vs **redesign 去 egress**：outbound offload 两条都不破坏；实现时勿在 PR 里顺手删 token egress。  
2. **smart max_attempts / interrupt**：verdict 写入必须在最终决策之后。  
3. **TypeEBPF 命名**：代码与文档统一称 `outbound_offload` / `OutboundOffload`，避免 `EBPFOutbound` 被理解成可路由 outbound type。  
4. **canary 116**：socket_assign + offload 同机验证；115 维持 rc41 token 直到显式升级。  

---

## 12. 立即下一步（执行顺序）

1. 合并本框架文档；option + stub 骨架 PR-A。  
2. 实现 P0 BPF + conn 钩子，netns 自测。  
3. P1 verdict 接入 connect + shared_network。  
4. 116 canary；指标对比后再谈打包进 rc42+。  

---

## 附录 A：名词对照

| 中文口语 | 正确指向 |
|---|---|
| ebpf 入站 / eBPF in | `type: ebpf` inbound |
| ebpf 出站 / eBPF out | **本框架 offload**，非 outbounds type |
| 出站 / egress | TC egress 程序（token 回写） |
| outbound | sing-box `outbounds[]` 配置项 |
| direct 下沉 | P1 flow verdict BYPASS |
| 内核转发 | P0 sockmap splice |

## 附录 B：最小 option 结构

```go
type EBPFOutboundOffloadOptions struct {
    Enabled      bool   `json:"enabled,omitempty"`
    SockmapTCP   *bool  `json:"sockmap_tcp,omitempty"`    // default true if enabled
    FlowVerdict  *bool  `json:"flow_verdict,omitempty"`   // default true if enabled
    DNSPrefill   bool   `json:"dns_prefill,omitempty"`    // default false
    MaxPairs     uint32 `json:"max_pairs,omitempty"`
    VerdictTTL   badoption.Duration `json:"verdict_ttl,omitempty"`
    FailOpen     *bool  `json:"fail_open,omitempty"`      // pin 失败回退 copy，默认 true
}
```
