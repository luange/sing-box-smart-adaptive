# sing-box v1.14.0-rc.4 性能与兼容性审查

## 范围

审查基线为官方 `v1.14.0-rc.4`（`193aba27f722028bc7cdc4e2b096522e11b12964`）。
自有分支在保留 Smart、Zig policy、eBPF v3、
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
3. **发布漂移**：Linux 发布工作流已改为匹配 rc4 gateway 标签，避免 rc4 核心
   推送后不触发精简 eBPF 构建。
4. **已建立连接卡住**：Smart 现在只在真实首个写入后启动单个有界计时器；
   首字节在 `established_stall_timeout`（默认 10s，5s–2m）内未到达时记一次
   失败并唤醒共享探测，首字节/关闭会取消计时，不主动制造流量。
5. **Smart 状态混淆**：Clash 扩展新增最多 32 个独立
   `network/site/transport` 上下文快照，旧的顶层字段仍保留为兼容视图。
6. **VMess WebSocket 崩溃**：修复失败升级返回 typed-nil `*WebsocketConn`
   导致清理路径空指针 panic，并避免并发健康检查修改共享 Header；异常网络
   分支也会关闭已建立连接。

### 107 transparent-huge-page regression (2026-08-30)

The RC4.1 process on VM 107 had only about 30 MiB of live memory at the
Clash `/memory` endpoint, but RSS had climbed to 260 MiB. `/proc/$pid/smaps`
showed a 181 MiB anonymous heap region backed by about 158 MiB of
`AnonHugePages`; the process had only 34 TCP and 9 UDP sockets. This was
retained transparent huge-page backing, not a DNS/session leak. The OpenRC
service now exports `GODEBUG=disablethp=1` (and the systemd unit does the same)
so released arenas can return to the kernel. After an atomic restart the same
binary stayed on version `1.14.0-rc.4-official-smart-ebpf-v3.45.1-stall-context`;
RSS was 73 MiB immediately and 82 MiB after 65 seconds, `AnonHugePages` was
4–8 MiB, both 9090/9091 remained listening, and Google/YouTube returned 204.

## 验证门

本分支不在 macOS 编译。提交 `0ef5c910` 已通过 Smart/Zig/C ABI CI 及
amd64/arm64 glibc/musl Linux 构建；提交 `ef21d5e4` 追加了 WebSocket typed-nil
回归测试。107 已在生产以 `0ef5c910` 产物运行，启动、9091 API、Google/YouTube
204 和 65 秒稳定性观察均通过，未出现新的 panic。eBPF 仍由内核 fast path
负责，代理节点流量不会错误套用 DNS prefill 的直连判定。
