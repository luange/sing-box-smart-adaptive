# 自动守护循环运行日志

## 2026-09-06 00:39 运行 #1(手动驱动,后续由 15 分钟定时任务接管)

### 一、codex 任务检测
- 仓库干净,HEAD=93798db5(此前已接手完成 codex 中断任务的 9 个提交)
- ~/.codex/sessions 无 09-06 活跃会话;最近的 09-05 会话 cwd 无关。判定无需续跑。

### 二、审查 → 测试 → 修复循环

**第 1 轮**(commit 7fc31837)
- tc.bpf.c 碎片包路径 PARSE_FAIL_PROXY 双重计数:显式 count_stat + handoff_proxy 内部 count_proxy 各计一次 → 删除显式计数
- native/bpf_util.c 共享 64KB verifier log_buf 非线程安全(v3/splice/inbound prepare 并发加载)→ 加 PTHREAD_MUTEX_INITIALIZER 并覆盖全部退出路径
- smart-engine policy.zig 恒真谓词 selection_mode<=1(Engine.init 已 clamp 到 0/1)→ 删除
- 验证:zig 25/25、go test ./... 全绿、race 绿、linux with_ebpf 构建 OK

**第 2 轮**(commit f523f0a3)
- token 模式(v1 data_plane="token")UDP 流关闭只删 shared_redirect,遗留 original_to_token / token_to_original 行:陈旧 token 地址的回包继续改写到失效 original,客户端端口复用会继承脏状态
- 新增 C 助手 sb_ebpf_shared_network_purge_token_flow:遍历 original_to_token,按身份字段匹配(任意 ingress ifindex),同时删反向行(恒 ifindex 0)与 original 行;DeleteRedirect 在 socket_assign 平面为 no-op
- originalDestination(40B)复用读 32B sb_shared_original_dst:补前缀契约注释(偏移断言本已存在)
- 验证:全绿

**第 3 轮**(commit 98d5d523)
- Lifecycle 双写顺序为内核先行;MemoryBackend.PublishStatic 在内核世代提交后失败会使两侧世代从不同基数永久发散 → 失败路径用 SyncPolicyGeneration(sink 世代)对账(PublishStaticRules/PublishStaticDirect/MergeStaticDirect 三处),该函数此前零调用方
- 验证:全绿

**第 4 轮**:拼接错误处理扫描(advisory 路径 debug 日志、fail-closed 路径返回)、splice peer-miss(fail-open SK_PASS + LRU,无需修)、verdict 常量使用——无新发现。

### 遗留观察(非缺陷)
- adapter/adaptive_pool.go、common/listener/listener.go 为历史遗留未 gofmt 文件,不属于本轮改动范围
- .bpf.o 内核对象需 Linux CI 重建(本机无法编译 tc.bpf.c/xdp.bpf.c);C 改动经 Linux CI `make -C common/ebpf generate check` 验证

## 2026-09-06 运行 #2(定时任务)

### 一、codex 任务检测
- 仓库 HEAD=d0dada78,工作区干净;~/.codex/sessions 无 24h 内活跃会话 → 无需续跑。

### 二、审查 → 修复循环

**第 5 轮**(commit ed144ac4)— 评分公式第 4 份副本对齐
- 发现 4 处 host 端 smartScoreForProfile 与 scoring.zig 的边界分歧:
  1. normalizedLogCost 对 ≤0/NaN/−Inf 返回 0(内核用 0.5 未知先验)——未测量节点看起来"免费";
  2. throughput/samples/reliability 非有限值未守卫;
  3. connect 为 0/亚微秒截断时 jitter 仍被信任(内核视为未知);
  4. 冷启动候选按 sqrt 衰减探索项(内核用全额预算)。
  全部对齐到内核语义。
- conformance reference.go 增加 profile 支持(bulk/udp 权重),新增
  TestSmartScoreForProfileMatchesReference:7 种估计形态 × 3 profile
  逐位钉死 host 分数,任何一侧漂移立即测试失败。

**第 6 轮**(commit 0baafef7)
- splice 统计下标在 splice.bpf.c / singbox_ebpf_out.h / outbound_abi.go
  三处重复 → TestSpliceStatIndexValues 值级钉死(Go 侧,防单侧重排)。
- abi.go 补小端序(bpfel-only)与 host-order 端口例外契约说明。

**第 7/8 轮**:BuildFlowPair/BankPublisher/generation 内部不变量审查——提交顺序注释、CAS SyncGeneration 回退保护均正确,无新发现。满足停止条件。

### 验证
go test ./... 全绿、-race 绿、smart_zig cgo conformance 绿、Zig 25/25、
GOOS=linux with_ebpf 全仓构建 OK。共 3 个提交(ed144ac4、0baafef7 及本轮内)。

## 2026-09-06 运行 #3(定时任务)

### 一、codex 任务检测
- 仓库 HEAD=60d0a02b,干净且已全部推送(origin 同步);无 24h 内活跃 codex 会话 → 无需续跑。

### 二、审查 → 修复循环

**第 9 轮**:dns_hint.go 全量审查——冲突隔离(proxy_refs+direct_refs→WEAK)、世代重置、TTL 过期清理、8192 上限 + LastSeen LRU 逐出、evidence 只升不降(无冲突时)——逻辑自洽,无缺陷。

**第 10 轮**:dns_prefill(OnDNSAnswer/dnsPrefillApply)——admission 槽位防 goroutine 风暴、Close 与异步发布的生命周期屏障、冲突时记录 proxy evidence、非直连地址也进冲突隔离、MACSourcePolicy 下禁用全局 promote(v3-control-plane-integrity 审计的闭环)——正确。

**第 11 轮**:verdict_learn(fail-closed 门:53 端口、MatchInputs 非 IP 类、process/user、非 bare-direct 全部 skip)+ 失效链路(重载 → RefreshV3Static/InvalidateFlowDirect;InvalidateAll 失败 → SetEnabled(false) 兜底;close → best-effort)+ smartStore(边界/锁/晚到观察的兼容写法)——无新发现。

**验证中发现并解决**(非代码缺陷):smart-engine/zig-out/lib/libsmart_engine.a 曾被 `-Dtarget=x86_64-linux-musl` 覆盖(部署准备),导致本机 `smart_zig cgo` 链接失败;按 host 目标重建后恢复。注意:在同一 worktree 切 zig 交叉目标会破坏本机 smart_zig 测试链路,交叉产物应使用独立 build root(zig build --prefix)。

**结论**:本轮审查(dns_hint / dns_prefill / verdict_learn / store / adaptive 解码)无新发现,全部测试绿:go test ./... 、race 4 包、smart_zig cgo conformance、GOOS=linux with_ebpf 构建。满足停止条件,无新提交。
