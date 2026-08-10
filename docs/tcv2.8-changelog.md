# 1.14.0-beta.12-smart-tcv2.8 更新日志

- 使用干净实现的 TC v2 替换生产共享网络 BPF 对象；支持 IPv4/IPv6、
  双 VLAN、TCP/UDP、socket assignment、DNS/主机/旁路 CIDR 和流判定。
- 保留 AF_XDP 可演进的共享解析器与 ABI，但当前不启用 AF_XDP；无驱动兼容
  性变化，失败路径继续回退内核/TC。
- 修复高频 DNS 源端口导致 1024 个 UDP NAT 会话和约 3000 个 goroutine
  常驻的问题。直接 DNS 默认窗口改为 16 会话、每会话 2 包。
- 新增 direct 入站参数 `udp_session_capacity`、`udp_queue_depth`，非标准 DNS
  端口也可明确使用小型窗口。
- 将每条 DNS UDP 源端口改为单请求/响应顺序处理；与 16 会话窗口组合后，
  不同客户端仍可并发，同时彻底消除 16×64 的内存放大。
- 保留 eBPF 数据 UDP 与 DNS UDP 的独立容量，避免 DNS 挤占 QUIC/数据会话。
- 依赖仓库地址统一为 `github.com/luange/*`。
- 未恢复已暂停的服务 capability；本版本重点是节点健康、数据面正确性和
  资源效率。
