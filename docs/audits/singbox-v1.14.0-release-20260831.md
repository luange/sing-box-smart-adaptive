# sing-box v1.14.0 正式版打包记录

## 基线

- 上游正式标签：`v1.14.0`
- 上游提交：`0b8995879f29a9b98ee027bc17b75e101445b238`
- 集成提交：`f9b92115773f779720fd02353ee6b5b8b17db70b`（保留本项目 Smart、Smart Zig、eBPF v3、provider、
  connection-history、Clash/Zashboard API 与 PBR 适配）
- 发布分支：`adaptive/official-v1.14.0-smart-ebpf`

## 构建配置

正式版通过 GitHub Actions 在 Ubuntu Linux 上构建，不在 macOS 本地编译。网关
精简标签仅包含当前部署需要的 gVisor、QUIC、DHCP、WireGuard、uTLS、Clash API、
connection-history、Tailscale、eBPF v3 与 Smart Zig；musl 产物为静态链接。
目标矩阵为 amd64/arm64 × glibc/musl。

发布前门禁包括：提交的 eBPF v2 provenance、Linux 重新生成、Smart Zig 单测与 C ABI、
Smart/传输回归测试，以及 amd64 glibc 的配置检查。eBPF 对象必须先通过 provenance
检查后才允许进入打包步骤，防止源码与 `go:embed` 对象漂移。

## 运行边界与部署记录

正式版产物已在 Linux CI 完成四架构构建并核对校验码。2026-09-03 已原子替换
VM107/VM115：两台运行 `sing-box 1.14.0`，Revision 为
`f9b92115773f779720fd02353ee6b5b8b17db70b`，部署二进制 SHA-256 为
`9550a73d428be2d37a62218f6ac12417c66114fb82cd2ec488d39fdd3b99e766`。
VM115 使用 eBPF v3 `socket_assign`，VM107 保留现有 tproxy 入站；两台均通过配置
校验、服务状态、API 可达性与最近错误日志门禁。
