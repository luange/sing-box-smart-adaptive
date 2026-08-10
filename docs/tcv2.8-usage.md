# Smart TC v2.8 使用说明

版本：`1.14.0-beta.12-smart-tcv2.8`

## 选择二进制

- `linux-amd64-glibc`：Debian、Ubuntu、PVE 虚拟机等 x86_64 系统。
- `linux-amd64-musl`：Alpine x86_64，静态链接。
- `linux-arm64-glibc`：Debian、Ubuntu、QNAP 等 ARM64 系统。
- `linux-arm64-musl`：Alpine ARM64，静态链接。

替换前必须执行 `sing-box check -c /path/to/config.json`，并用
`sha256sum -c SHA256SUMS` 校验文件。生产实例只保留最近两个旧核心。

## Smart 节点筛选和权重

`exclude_nodes` 支持完整节点名或关键词；匹配到的节点不会进入 Smart
候选。`node_weights` 用于降低或提高候选优先级，权重必须大于 0；低于
1 表示降权，高于 1 表示加权。

```json
{
  "type": "smart",
  "tag": "US",
  "outbounds": ["US-01", "US-Gcore-02", "US-03"],
  "exclude_nodes": ["已知故障节点完整名"],
  "node_weights": [
    { "match": "Gcore", "weight": 0.25 },
    { "match": "Misaka", "weight": 0.8 }
  ],
  "probe_interval": "5m",
  "probe_timeout": "5s",
  "site_stickiness": "15m"
}
```

节点画像在同一进程内按 Endpoint 共享，进程退出后全部重建；不会读取
上一次进程留下的健康结论。真实连接失败会写入共享画像并触发降权。

## eBPF 共享网络入口

```json
{
  "type": "ebpf",
  "tag": "PA-in",
  "network": ["tcp", "udp"],
  "udp_timeout": "1m",
  "udp_session_capacity": 512,
  "dns_session_capacity": 16,
  "dns_mode": "hijack",
  "shared_network": {
    "enabled": true,
    "include_interface": ["pa-hk", "pa-us", "pa-jp", "pa-sg", "pa-other"],
    "data_plane": "socket_assign",
    "flow_verdict": true,
    "drop_udp_443": false
  }
}
```

`socket_assign` 是默认模式。`token` 仅用于显式兼容回退。TC v2 对
IPv4/IPv6、最多两层 VLAN、TCP/UDP 做有界解析；分片和不能确定的包回退
内核路径。AF_XDP 只保留 ABI/解析器兼容边界，当前版本没有启用 AF_XDP，
因此不会改变网卡驱动兼容范围。

## DNS UDP 内存控制

高频 DNS 客户端通常每次查询更换源端口。通用 UDP 的 1024 会话和 64 包
队列会无意义地保留大量 goroutine 与缓冲。直接 DNS 入站应显式使用小型
请求/响应窗口：

```json
{
  "type": "direct",
  "tag": "dns-in",
  "listen": "0.0.0.0",
  "listen_port": 53,
  "udp_timeout": "5s",
  "udp_session_capacity": 16,
  "udp_queue_depth": 2
}
```

端口 53 在未填写这两个参数时自动采用 `16/2`；每条 DNS UDP 源端口按
请求/响应顺序一次处理 1 个异步查询，避免“会话数 × 64 查询”再次放大内存。
不同源端口仍由会话池并发处理。其他端口保持通用默认值
`1024/64`。非 53 的 DNS 端口（例如 5353）应显式填写。容量最大 4096，
队列深度范围 1–256。

## 内存回收

```json
{
  "experimental": {
    "debug": { "memory_limit": "128M" },
    "clash_api": {
      "memory_reclaim": {
        "enabled": true,
        "check_interval": "1m",
        "cooldown": "5m",
        "minimum_process_age": "5m",
        "minimum_idle": "32MB",
        "maximum_heap_alloc": "220MB",
        "consecutive_eligible": 2
      }
    }
  }
}
```

该机制只回收已经空闲的 Go 堆页，不删除连接或 Smart 状态。可从 Clash API
`/memory/details` 查看当前堆、goroutine 和回收计数。

## 上线门禁

1. 配置检查与版本/SHA 校验。
2. DNS 并发查询没有失败。
3. Google `generate_204` 返回 204，YouTube 首页返回 200。
4. 观察 RSS、FD、线程、goroutine，不得随负载结束后持续单调增长。
5. 检查 panic、fatal、socket-assign failure 和 Smart 连续业务失败。

TLS 首页成功只能证明连接与 TLS 可用，不等于已完成 YouTube signed Range、
ChatGPT/Claude 登录态或上传/流式业务认证。服务 capability 默认关闭时不要
宣称这些门禁已经覆盖。
