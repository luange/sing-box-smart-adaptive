# TCv2、Smart 连接生命周期与 DNS 复用

本版本把控制面选择与数据面连接生命周期分开：Smart 负责消费共享节点画像并选择候选；连接是否中断由独立策略决定；TCv2 失败时放行到原网络栈，不以丢包掩盖控制面错误。

## Smart 选择性切换

推荐配置：

```json
{
  "type": "smart",
  "tag": "US",
  "outbounds": ["US-1", "US-2"],
  "interrupt_policy": {
    "mode": "selective",
    "idle_threshold": "10s",
    "long_connection_age": "30s",
    "grace_period": "3s"
  }
}
```

`mode` 支持：

- `none`：切换只影响新连接。
- `selective`：关闭旧候选上的空闲连接；短活跃连接获得 `grace_period`；超过 `long_connection_age` 且仍活跃的长连接保留。节点连续三次探测失败或连续三次真实拨号失败时，强制关闭该节点在同一网络、服务族和传输协议中的连接。
- `all`：每次切换立即关闭旧候选在同一网络、服务族和传输协议中的连接。

旧参数 `interrupt_exist_connections` 仍可读取：`true` 等价于 `mode=all`，但新配置应使用 `interrupt_policy`。切换日志和 Clash API 只记录节点、原因与计数，不记录 URL 查询参数、令牌或凭据。

## DNS UDP 事务复用

直连与 eBPF 入站的 53/UDP 不再按客户端源端口建立完整 UDP NAT 会话。相同客户端地址（共享网络场景再加入口接口）复用一个有界 lane，通过 DNS 事务 ID 与 question 指纹把响应送回原请求。该路径具有队列和在途事务上限，超限会统计并拒绝新事务，不会无限增加 goroutine 或堆。

普通数据 UDP 仍使用 sing 的 UDP NAT，保持代理节点 UDP 语义；运行日志额外输出 data/DNS 会话、事务、准入拒绝和队列丢弃计数。

## TCv2 行为

- TCP 已建立流先查找原 socket；新流才交给监听 socket。
- original-destination 使用非 LRU HASH，并在用户态成功消费后删除。
- IPv6 支持有限扩展头遍历；分片和无法解析的包 fail-open。
- map 更新、listener 查找或 socket assign 失败均 fail-open，并增加 `fallback_open` / `original_dst_lost` 计数。
- `drop_udp_443` 默认关闭，只有明确需要禁用 QUIC 时才设为 `true`。

生产观察重点是业务连续性、`fallback_open`、`original_dst_lost`、DNS/数据 UDP admission rejected、队列丢弃、goroutine、HeapAlloc 与 RSS 的负载相关趋势。
