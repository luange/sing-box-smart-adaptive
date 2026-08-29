# sing-box v1.14.0-rc.2 性能与兼容性审查

## 范围

审查基线为官方 `v1.14.0-rc.2`（`f5b8b7a57922084361907a13273f2c88f35ae7c7`）。
自有分支通过合并提交 `a1123ecf` 接入 rc2，并保留 Smart、Zig policy、eBPF v3、
provider、connection-history、Clash/Zashboard API 和 PBR 适配层。没有把代理协议
栈重复改写成第二套实现。

## 上游改动核对

rc2 的 QUIC 拥塞控制、FakeIP UDP 回程映射、异步 DNS/本地缓存分区、DNS TCP
连接复用、UDP 批处理、URLTest 阻塞修复、DNS 乐观缓存和 tproxy UDP 回写缓存均
已在合并树中；自有扩展只在相应边界补充观察、画像和卸载逻辑。

## 已整改的瓶颈

1. **Smart 选路锁竞争**：`rankPooled` 原来对每个候选重复读取
   `candidateProbeKey`，一轮最多三次读锁。现在在同一个候选快照边界复制一次
   identity 表，后续画像、死探测和 Zig 选择均复用快照；语义不变，减少大组
   的锁往返。
2. **DNS prefill goroutine 放大**：每个 DNS 答案原来直接创建 goroutine，突发
   查询会把堆和调度器放大。现在采用两个有界 worker slot，满载时丢弃 advisory
   hint（fail-open），关闭时等待已接纳任务完成，并记录
   `dns_prefill_queue_drops`。
3. **发布漂移**：Linux 发布工作流已改为匹配 rc2 gateway 标签，避免 rc2 核心
   推送后不触发精简 eBPF 构建。

## 验证门

本分支不在 macOS 编译。合并后必须在 Linux CI 运行 Go 全量测试、Smart race
测试、eBPF verifier/数据面测试及 amd64/arm64 glibc/musl 构建；通过后才允许
替换生产 VM。eBPF 仍由内核 fast path 负责，代理节点流量不会错误套用 DNS
prefill 的直连判定。
