# sing-box v1.14.0 正式版打包记录

## 基线

- 上游正式标签：`v1.14.0`
- 上游提交：`0b8995879f29a9b98ee027bc17b75e101445b238`
- 集成提交：`7a516fea`（保留本项目 Smart、Smart Zig、eBPF v3、provider、
  connection-history、Clash/Zashboard API 与 PBR 适配）
- 发布分支：`adaptive/official-rc5-smart-ebpf-audit`

## 构建配置

正式版通过 GitHub Actions 在 Ubuntu Linux 上构建，不在 macOS 本地编译。网关
精简标签仅包含当前部署需要的 gVisor、QUIC、DHCP、WireGuard、uTLS、Clash API、
connection-history、Tailscale、eBPF v3 与 Smart Zig；musl 产物为静态链接。
目标矩阵为 amd64/arm64 × glibc/musl。

发布前门禁包括：提交的 eBPF v2 provenance、Linux 重新生成、Smart Zig 单测与 C ABI、
Smart/传输回归测试，以及 amd64 glibc 的配置检查。eBPF 对象必须先通过 provenance
检查后才允许进入打包步骤，防止源码与 `go:embed` 对象漂移。

## 运行边界

本次仅更新正式版源码与发布产物；未自动替换 VM107/VM115 的生产核心。生产部署仍
沿用上一版可回滚包，待四架构产物和校验码核对完成后再单独授权切换。
