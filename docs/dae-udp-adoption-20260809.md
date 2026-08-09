# DAE-inspired UDP lifecycle redesign

日期：2026-08-09

## 结论

DAE 的主要收益不是把代理 UDP 会话变成“零成本”，而是把可在内核决定的流尽早结束在 TC/eBPF 路径，避免进入用户态代理；必须经过代理的 UDP 仍然需要端点、缓冲和协程。参考：[DAE 工作原理](https://github.com/daeuniverse/dae/blob/main/docs/zh/how-it-works.md)、[TC tproxy 实现](https://github.com/daeuniverse/dae/blob/main/control/kern/tproxy.c)。

本分支采用两层设计：

1. `shared_network.flow_verdict` 仅在 `socket_assign` + `outbound_offload.verdict.mode=learn` 下启用。首个真实 TCP 或 UDP 流经用户态并确认 DIRECT 后，按精确五元组、generation 和单调过期时间写入内核 map；后续同一流直接由 TC 通过，不绕入透明代理。接口变化会递增 generation，使旧 verdict 立即失效。TCP/UDP、IPv4/IPv6 共用同一 ABI 和失效规则。
2. 代理侧 UDP NAT 不再使用“满容量踢掉最久未使用活动会话”的 LRU。改为 64 分片生命周期表：活动会话只在自身结束或空闲 deadline 到期时移除；达到容量时拒绝新会话并保留已有流。端点关闭时立即从表中移除，janitor 仅作为兜底。这对应 DAE 的 endpoint pool（见[UDP endpoint pool](https://github.com/daeuniverse/dae/blob/main/control/udp_endpoint_pool.go)）。

## 为什么不照搬 DAE

- DAE 的内核 fast path 适合其 TC 路由模型；本项目仍需要 sing-box 的透明代理、Smart/AdaptivePool 和多入口上下文，因此只吸收精确流缓存、generation、懒过期和生命周期清理。
- 不使用 sockmap/sk_msg：DAE 源码明确避免在目标内核上引入该路径的稳定性风险。
- 不使用无条件定时 `FreeOSMemory`，不把活动 QUIC 会话强制缩短，也不把 UDP 接收缓冲降到会截断数据报的尺寸。

## 压力策略

容量是 admission budget，不是强制驱逐阈值。满载时新建流会被丢弃并等待后续空闲流释放；已有 DNS、QUIC 和数据流不会因另一个新流到来而被关闭。这是可感知的稳定性取舍：峰值期间新流可能失败，但不会造成大量连接同时 reset、重连风暴和更高 RSS。

## 验证门禁

- `go test ./common/udpnat2` 与 `go test -race ./common/udpnat2`
- PVE Linux：`make -C common/ebpf generate`、`make -C common/ebpf check`
- PVE：`go test -tags with_ebpf ./common/ebpf ./protocol/ebpf ./option`
- PVE race：同一组 `go test -race -tags with_ebpf ...`
- PVE `go vet -tags with_ebpf ...`
- eBPF verifier：`TestBackendProgramLoadIntegration` 通过
- shared-network 数据路径：`TestSharedNetworkDataPathIntegration` 通过

目前只完成隔离构建与测试，尚未启用生产配置；必须在 VM117 做 UDP/QUIC 长连接、容量满载、新流拒绝、接口变更 generation 失效和 RSS/FD/协程趋势验证后，才可考虑灰度。
