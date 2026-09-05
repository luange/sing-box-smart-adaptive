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
