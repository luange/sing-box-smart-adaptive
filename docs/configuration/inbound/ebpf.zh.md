---
icon: material/lan-connect
---

# eBPF

eBPF 入站通过 cgroup socket-address 程序拦截本机产生的 TCP 和 UDP 流量。
可选的 `shared_network` 模式代理来自指定下游接口的转发流量。推荐的
`socket_assign` 数据面在 TC ingress 保留原始五元组，通过 SOCKMAP 把流量交给透明
listener，并只用独立 mark/路由表完成本机投递；不挂 TC egress，也不改写回包。
兼容的 `token` 数据面仍使用 ingress/egress 令牌改写。两种模式都不使用 TUN、
iptables、loopback TC 或 SOCKS 中间层。

此入站用于以 root 权限直接运行 Android 或 Linux 原生 sing-box 二进制的场景。
构建时必须启用 cgo 和 `with_ebpf` 构建标签。

## 结构

```json
{
  "type": "ebpf",
  "tag": "ebpf-in",

  ... // 监听字段

  "network": "",
  "dns_mode": "hijack",
  "cgroup_path": "",
  "capture_local": true,
  "redirect_address": [
    "127.128.0.0/9",
    "fd53:696e:672d:626f::/64"
  ],
  "bypass_rule_set": [
    "geoip-cn"
  ],
  "include_uid": [],
  "include_uid_range": [],
  "exclude_uid": [],
  "exclude_uid_range": [],
  "shared_network": {
    "enabled": false,
    "include_interface": [],
    "data_plane": "socket_assign",
    "routing_mark": 1396834305,
    "routing_table": 2026
  },
  "outbound_offload": {
    "splice": {
      "enabled": false
    },
    "verdict": {
      "mode": "off"
    }
  }
}
```

### 监听字段

参阅[监听字段](/zh/configuration/shared/listen/)了解可用字段。

eBPF 入站在内部使用从 `redirect_address` 中选取的地址。因此，`listen`
可以省略或设为未指定地址（`0.0.0.0` 或 `::`）。入站会根据
`redirect_address` 启用的地址族创建 IPv4 和/或 IPv6 通配 listener。

`listen_port` 默认为 `65532`。值为 `0` 时同样使用此默认值；不支持随机监听
端口，因为加载 eBPF 程序时会把重定向端口写入程序。

不支持 `proxy_protocol` 和 `proxy_protocol_accept_no_header`，因为被拦截的应用
连接不包含 Proxy Protocol 头。

不支持 `netns`。cgroup hook 和重定向路由作用于当前网络命名空间，无法限定到
监听字段指定的网络命名空间。

`bind_interface` 可以省略或设为 `lo`。不支持其他接口，因为重定向连接通过
loopback 接口交付。

配置的 `udp_timeout` 和 `detour` 会像其他 UDP 入站一样作用于被拦截的 UDP 会话。

### 字段

#### network

监听的网络协议，`tcp` `udp` 之一。

默认所有。

未被 `network` 选中的协议会绕过 eBPF 入站。

`shared_network` 在 `dns_mode` 为 `hijack` 时必须启用 UDP，因为热点 DNS
由代理处理。

#### dns_mode

DNS 处理模式。可选值：

| 模式 | 行为 |
|------|------|
| `hijack` | 在目标地址及 `bypass_rule_set` 检查之前拦截 TCP/UDP 目标端口 53。 |
| `off` | 始终放行 TCP/UDP 目标端口 53。 |

默认值为 `hijack`。

此模式只作用于 `network` 已启用的协议。socket 保护、UID 包含/排除策略、Android
`dns_tether` 排除及 DHCP 安全绕过仍先于 DNS 处理执行。`hijack` 模式下，目标端口
53 随后优先于未指定、本机、私网、多播及 `bypass_rule_set` 目标检查，避免 DNS
服务器地址恰好位于绕过 CIDR 中时查询绕过 sing-box 而泄露。

同一模式也作用于 `shared_network`。热点场景建议保持默认的 `hijack`；只有主机已
提供可用的独立 DNS 服务，并且明确希望热点 DNS 不经过 sing-box 时才应使用 `off`。
`off` 模式不会代理热点 DNS，如果没有独立 DNS 路径，查询可能泄露或失败。

关于该选项的数据路径、性能边界以及与 dae、TUN、Redirect 和 TProxy 的区别，参阅
[eBPF 入站实现对比](/manual/misc/ebpf-inbound-comparison/)。

#### cgroup_path

需要拦截其本机流量的 cgroup v2 层级绝对路径。留空时，sing-box 自动发现
cgroup2 挂载点并使用其根层级。在标准 Linux 上，如不希望拦截系统全部本机流量，
可把指定服务放入专用 cgroup 并配置此路径。此字段不限制 `shared_network`
选中的转发流量。

#### capture_local

是否加载并挂载 cgroup 程序以截获本机进程产生的连接。默认值为 `true`。

仅把 sing-box 用作 PBR/旁路由、并通过 `shared_network` 接收下游客户端流量时，
建议设为 `false`。此时不会打开或锁定 cgroup，也不会加载本机 connect/sendmsg/
recvmsg 程序；管理探测、SSH、DNS 和升级流量保持在控制面。TC ingress/egress
程序仍会挂载到 `shared_network.include_interface`，转发数据面不受影响。

`capture_local` 为 `false` 时必须启用 `shared_network`，且不得配置
`cgroup_path`、`include_uid`、`include_uid_range`、`exclude_uid` 或
`exclude_uid_range`；无效组合会在启动前报错。

#### include_uid

需要拦截的进程 UID 列表。

当 `include_uid` 或 `include_uid_range` 非空时，未被这两个字段匹配的 UID
产生的流量会绕过 eBPF 入站。

#### include_uid_range

需要拦截的进程 UID 范围列表，格式为 `start:end`。

#### exclude_uid

需要绕过的进程 UID 列表。

exclude 规则的优先级高于 include 规则。

在 Android 上始终自动排除 UID `1052`（`dns_tether`），避免平台热点 DNS 服务
和热点客户端的回包进入本机 cgroup 重定向；此排除不依赖 `shared_network`。

#### exclude_uid_range

需要绕过的进程 UID 范围列表，格式为 `start:end`。

UID 规则匹配执行 socket 操作的进程有效 UID。UID 范围会被压缩为 eBPF LPM
trie 条目，不会展开为逐 UID 条目。

#### bypass_rule_set

目标 IP CIDR 条目需要绕过 eBPF 入站的规则集列表。

启动时，sing-box 调用现有的规则集 CIDR 提取接口，将结果合并到 IPv4 和 IPv6
eBPF LPM trie map。目标地址命中任一 map 时，cgroup 程序保持原始目标不变；
应用 socket 直接使用内核网络栈，不会进入 eBPF listener、嗅探、普通路由规则
或出站。

此字段执行的是 CIDR 提取，并不执行完整规则集匹配。仅提取目标 `ip_cidr` 和
二进制 IP set 条目；eBPF 程序不会判断域名、端口、网络、进程、来源、逻辑分组
或反选条件。特别是，当 `ip_cidr` 与其他条件组合时，CIDR 仍会被单独提取，
其他条件不会保留。因此，此字段应只引用纯 CIDR 规则集。

多个规则集及其中提取出的所有 CIDR 按并集合并。选择 `direct` 出站的普通
路由规则不会自动下沉；只有此处显式列出的规则集会启用内核直连绕过。

引用的本地或远程规则集重新加载后，sing-box 会再次提取 CIDR 并原地更新 map，
无需重新加载或挂载 eBPF 程序。若更新无法应用，会记录错误并保留上一次成功
应用的策略。

此绕过只作用于经过 cgroup socket-address hook 的本机流量。Android 热点的
转发流量不经过这些 hook。

#### redirect_address

将被拦截连接重定向到 sing-box listener 时使用的内部地址前缀。

每个地址族最多配置一个前缀。配置 IPv4 前缀会启用 IPv4 拦截，配置 IPv6
前缀会启用原生 IPv6 拦截，同时配置两者则启用双栈拦截。IPv4-mapped IPv6
socket 按 IPv4 处理。

省略时使用 `127.128.0.0/9`，且仅启用 IPv4 拦截。目前 IPv4 前缀必须在
`/8` 到 `/10` 之间，IPv6 前缀必须为 `/64`。

这些前缀是流量令牌地址池，并不是 TUN 入站所使用的接口子网。无连接 UDP 根据
原始地址、端口和协议确定性生成稳定的主机令牌，发往同一目的地的后续数据包会
复用已有 map 条目。TCP 和已连接 UDP 还会把 socket `SO_COOKIE` 混入令牌，避免
发往同一目的地的并发 socket 错误共享生命周期状态。

redirect map 不会淘汰或覆盖已有条目。令牌冲突时最多执行八次确定性探测；map
容量耗尽时会拒绝新流量，而不会将其错误路由到其他目的地。较大的前缀可使热路径
通常只需一次探测。默认值使用 IPv4 回环范围中较少被显式使用的后半段，同时保留
23 位令牌空间；IPv6 示例使用 sing-box 专用的 ULA 前缀。自定义前缀不得与设备
需要访问的任何目的网络重叠。

redirect 条目会按照实际所有者回收。TCP listener 读取原始目的地址后立即删除对应
条目；无连接 UDP 条目在 sing-box UDP NAT 会话之间进行引用计数，并在最后一个
会话关闭时删除；已连接 UDP 以 socket cookie 保存 redirect 令牌，并在应用 socket
关闭时由 cgroup socket-release 程序删除 redirect、令牌和 peer cache 条目。UDP
socket 重新 connect 时，也会先删除此前的已连接映射再安装新映射。

sing-box 会在当前网络命名空间中，通过 loopback 接口为每个配置前缀自动添加
`RTN_LOCAL` 路由。若已有本地路由能够覆盖该前缀则直接复用；关闭时只删除由
当前入站创建的路由。

除 `dns_mode: hijack` 下的目标端口 53 外，本机 cgroup 路径始终绕过未指定、回环、
多播以及当前本机接口网段，并在网络变化后刷新这些网段。UDP 端口 67、68、546
和 547 也始终绕过。因此，只开启 eBPF 入站而不开启 `shared_network` 时，不会挂载
TC、修改 `route_localnet`、代理热点客户端，也不会干扰热点 DHCP/DNS。

同一 cgroup 层级同时只能由一个 eBPF 入站管理。sing-box 会在入站生命周期内
独占锁定配置的 cgroup 目录。只有成功取得该锁后，才会清理由异常退出遗留的
sing-box eBPF 程序，因此启动第二个实例不会卸载仍在运行的实例所挂载的程序。

sing-box 会把自身创建的 socket 的 `SO_COOKIE` 登记到 eBPF LRU map。cgroup
程序在重定向前查询此 map，从而避免 sing-box 的出站连接和 UDP listener
再次被捕获。

对于本机重定向连接，sing-box 会保留 socket 的源端口，并使用发起连接的 UID 查询
原目标路由，以路由首选源地址替换 listener 所见的 loopback 源 IP。这使
`source_ip_cidr` 路由规则和 Clash API metadata 保持有效，也能适配 Android 的 UID
策略路由。如果路由查询失败，
连接不会被拒绝，而是继续使用 listener 观察到的 loopback 源地址。显式绑定的非
loopback 源地址会原样保留。

#### shared_network

用于热点或其他共享下游网络的可选转发代理。关闭或省略时，不会创建共享 listener、
`clsact` qdisc、TC filter 或修改 sysctl。

此模式同时支持 Android 和标准 Linux。在标准 Linux 上，它为已有路由 LAN、无线 AP
或网关后的客户端提供 TC 透明代理；它本身不会创建下游网络，也不会自动把主机配置成
路由器。

启用后，`include_interface` 必须列出一个或多个 Ethernet-like 下游接口。不要选择
`lo`、上游接口或 TUN、WireGuard、PPP、IPIP 等纯三层设备。接口可以在启动时尚未
出现；此时 eBPF 入站会正常启动并等待，不启用 shared 数据面。已挂载的接口消失后，
sing-box 会卸载其状态，同时保持本机 eBPF 入站运行；同名接口重新出现后会自动重新
挂载。sing-box 会在网络变化后及每三秒重新同步接口列表。

应选择客户端帧实际进入 TC ingress 的接口。Linux bridge 场景通常需要选择面向客户端
的各个 bridge port，而不能假定 bridge master 一定能看到这些 ingress 帧；具体 hook
路径取决于 bridge 和驱动。此模式面向客户端以本机为网关的路由下游网络，并非任意的
二层透明网桥。

`data_plane: socket_assign` 是推荐模式。它只挂 TC ingress：先保存原目标和入口接口，
再用 `bpf_sk_assign` 交给 IPv4/IPv6 TCP/UDP 透明 listener，并设置专用 mark 进入独立
local 路由表。数据包五元组保持不变，回包直接由内核透明 socket 产生，因此没有
egress NAT、校验和重算或 GSO 改写。`routing_mark` 和 `routing_table` 为零时分别使用
`0x53420001` 和 `2026`；启动会预检优先级 9000 的规则及路由表占用，发现不兼容状态
会拒绝启动且回收本进程已创建的项目，不会覆盖第三方规则。

`data_plane: token` 是兼容模式：先挂 egress 再挂 ingress，ingress 将目标改写为逐流
令牌和随机 listener 端口，egress 在回包恢复原始源地址。两种模式的原目标查询键均
包含客户端地址和端口，不同下游客户端不会错误共享状态。

DHCP 端口 67、68、546 和 547 始终绕过 TC。`dns_mode: hijack` 下，目标端口 53
会在本机地址、私网及 `bypass_rule_set` 判断之前被捕获，包括发给热点网关的 DNS
查询；`dns_mode: off` 下，目标端口 53 始终走普通转发路径。其他本机、私网、链路
本地、多播和已配置绕过 CIDR 也仍走普通转发路径。

`token` 模式的 IPv4 令牌使用配置的回环重定向前缀。仅当
`net.ipv4.conf.<interface>.route_localnet` 原值为关闭时，sing-box 才会临时启用，
并在 ingress、egress filter 都卸载后恢复；原本已启用的值不会被修改。IPv6 使用
配置的 ULA 令牌前缀及此入站管理的本地路由。只有 `redirect_address` 显式包含 IPv6
`/64` 时才会启用 IPv6 拦截；默认 redirect 配置仅启用 IPv4。

实现会创建或复用 `clsact`，关闭时不会删除它，因此其他 TC filter 保持不变。
使用 TC 优先级 `1`、ingress handle `0x5342` 和 egress handle `0x5343`。绕过流量
返回 `TC_ACT_PIPE` 以继续后续 filter，被捕获流量返回 `TC_ACT_OK`。数字更小的
优先级仍会先执行；sing-box 不会替换占用上述 handle 的其他 filter。

优先级 `1` 会使 sing-box 先于 Android AOSP tethering TC offload（IPv6 优先级 `2`、
IPv4 优先级 `3`）执行。Android 可以在首个连接前建立 IPv6 `/128` 转发表；如果
sing-box 排在其后，公网 IPv6 会先被直接重定向到上游。发给热点网关的 DNS 不属于
这种转发流量，因此“只能看到 IPv6 DNS、看不到后续公网 IPv6 连接”通常意味着公网
流量已被更早的 tethering offload 路径取走。

系统仍负责创建热点或 bridge、IP forwarding、IPv4 NAT、IPv6 RA/NDP、DHCP，以及
`shared_network` 关闭时使用的 DNS 服务。绕过 Linux TC 的 XDP 或硬件热点卸载无法
代理；应在每种 Android 内核上验证实际下游接口及双向流量。在标准 Linux 上还应验证
所选 bridge port 的 hook 路径，以及是否已有优先级 `1` 的 TC filter。

#### outbound_offload

可选的模块 B/A 协调器，挂在本入站下（**不是**可路由的出站类型）。默认所有 offload
路径均为 **关闭**。

##### outbound_offload.splice

| 字段 | 默认 | 说明 |
|---|---|---|
| `enabled` | `false` | SOCKMAP / `sk_skb` stream parser+verdict 中继。失败 fail-open 到用户态 copy。 |
| `accounting` | `true` | PERCPU 字节 map。为 false 时永不触碰 bytes map。 |
| `half_close` | `close` | `close` = 对端 FIN 时两侧一并关闭。`passthrough` **当前等价于完全不启用 splice**（不 attach SOCKMAP）；真半关转发尚未实现，枚举值仅为将来保留。 |
| `allow_outbound_types` | `["direct"]` | 显式出站类型白名单。组出站仅在列表中时才放行。 |
| `max_pairs` | `65536` | 并发 pair 上限（`0` = 默认）。 |
| `idle_timeout` | `10m` | 已 splice pair 的空闲 watchdog。 |

**准入条件（全部满足）：** TCP；两端均为裸 `*net.TCPConn`；入站类型仅 `ebpf`
（redirect/tproxy 未授权，除非另有 lab 证据）；出站类型在 `allow_outbound_types` 内；
无 TLS fragment/spoof；用户态 drain 后内核 recvq 为空（FIONREAD）；能力探测 OK。

`bpf_sk_redirect_hash` 的 flags 固定为 `0`（egress）。IPv4 与纯 IPv6 pair 在内核
成功加载 SOCKMAP 程序时均可用（加载失败 fail-open）。

##### outbound_offload.verdict

流级 verdict 卸载（模块 A）。缓存“该目的地为 direct”，使后续 connect 可跳过用户态。
**默认 `off`（F-1）。** 错误写入会让流量静默绕过 route/log/clash-api —— 下列安全门
为强制要求。

**粒度（A3 / F-3）：** key 仅为 **destination 级** `{family, protocol, port, addr}`，
不是 per-UID / per-flow / per-netns。学到一条 DIRECT 后，该 cgroup 捕获面上所有到
该目的地的流都会跳过捕获。仅适合全局直连网关画像；否则保持 off。

| 字段 | 默认 | 说明 |
|---|---|---|
| `mode` | `off` | `off` — 关闭。`learn` — 在 **eBPF 入站**、空 direct 拨号成功后写入 `(dst_ip, dst_port) → DIRECT`（TTL）。除 `off`/`learn` 外的值（含历史 `dns`）在解析阶段 **直接拒绝**。 |
| `ttl` | `5m` | 相对 **`bpf_ktime_get_ns` / CLOCK_MONOTONIC** 的生命周期（禁止 wall clock；A1/F-2）。 |
| `max_entries` | `65536` | LRU map 容量（接入 map create；`0` → 默认）。 |
| `allow_with_sniff` | `false` | **已弃用（Q3 P4）**。保留字段兼容旧配置。**不再**放宽域名/协议/进程类 learn 门。路由 `MatchInputs` 为准：仅 IP/端口/网络类决策可学；域名类永不学。仅在没有任何规则 item 写入 MatchInputs 时，软化旧的 sniff 元数据启发式。 |

**安全门（跳过写入并计 skip，永不报错）：**

1. 目的端口 **53** 永不写入（与 DNS hijack 共存）。
2. 若 sniff 元数据参与且 `allow_with_sniff` 为 false → skip。
3. 出站必须是空 `direct`（`dialer.DirectDialer` 且 `IsEmpty()==true`，含 stock DIRECT）。
4. 存在进程/用户元数据（`ProcessInfo` / `User`）→ skip。
5. **仅 `inbound type == ebpf`** 可 learn（A4）；mixed/socks/tun 不能污染 map。

**失效：** 接口更新 / coordinator close 时 `generation++`；内核 TTL 过期；调试用
Export 最近写入。

**内核路径：** `connect4` 在 dest bypass 之后、CIDR 之前查 `sb_out_verdict`。命中
`DIRECT` 且 generation 匹配且未过期 → return 1（不捕获）并递增内核 `hits`。
不匹配/过期递增 `gen_mismatch` / `expired`。`udp4` 有同样查表但 **截至 rc45 无 UDP
learn 写入者**（A7）——仅 miss。周期日志：`eBPF outbound verdict metrics: … kernel_hits=…`。

**证据（F-5）：** 声明 verdict 有效必须附 `kernel_hits>0` + 应用层 n/n +
`InvalidateAll` 后 hits 停止增长。示例配置中 **禁止** 写 `"mode": "learn"`（默认 off）。

## 构建

继续使用现有的 `make build` 目标。构建时需要启用 cgo，并在平时使用的
构建标签中追加 `with_ebpf`。例如，在 Linux 上保留 sing-box 标准构建标签：

```sh
CGO_ENABLED=1 \
TAGS="$(cat release/DEFAULT_BUILD_TAGS_OTHERS),with_ebpf" \
make build
```

为 Android 构建时，在同一个 `make build` 目标上指定目标架构和 Android NDK
编译器：

```sh
CGO_ENABLED=1 \
GOOS=android \
GOARCH=arm64 \
CC="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android33-clang" \
TAGS="$(cat release/DEFAULT_BUILD_TAGS_OTHERS),with_ebpf" \
make build
```

当 `TAGS` 包含 `with_ebpf` 时，`make build` 会先使用 `-target bpfel` 编译 TC
程序，因此需要支持 BPF 后端的 Clang 和 Linux UAPI 头文件。生成的对象文件由 Git
忽略，不属于源码树内容。

设备内核必须提供 cgroup2，以及配置的地址族和 `network` 所需的 cgroup
attach type：connect4/connect6；启用 UDP 时还需要 UDP4/UDP6 sendmsg、recvmsg
和 `BPF_CGROUP_INET_SOCK_RELEASE`。进程需要创建并挂载 BPF map/program 以及
管理本地路由的权限。`shared_network` 还需要 sched_cls TC、`clsact`、IPv4 下可写
的逐接口 `route_localnet` 和 `CAP_NET_ADMIN`。

## 鸣谢

感谢 [Asterisk4Magisk/bpf2socks](https://github.com/Asterisk4Magisk/bpf2socks)
项目提供了本入站所基于的原始 eBPF 流量拦截实现。
