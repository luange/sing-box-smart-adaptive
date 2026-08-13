# TC v2 Claude 审查整改记录（2026-08-13）

## 结论

TC v2 已从“仅嵌入、实际运行 v1”改为 `data_plane: socket_assign` 时真实加载
`sb_share_v2_in`。token 模式继续加载 v1，两种数据面不再混用对象或 map ABI。

## 审查项处置

| 审查项 | 处置 | 验证 |
|---|---|---|
| A v2 死代码 | loader/runtime 按数据面选择 v1/v2；CI 和 VM117 的 TC filter 均显示 `sb_share_v2_in` | 内核 verifier、真实 TC attach |
| B bypass/fail-open mark 污染 | mark 只在 `sk_assign` 成功后设置 | fail-open 分支检查、netns 数据路径 |
| C1 SOCKMAP release | 保留 `bpf_sk_release`；Ubuntu 24.04 verifier 明确把 SOCKMAP lookup 标为 `ref_obj_id`，删除 release 会报 `Unreleased reference` | system Clang 与 NDK Clang 21 verifier |
| C2 UDP 每包 map 写 | 已存在 tuple 不再 update；仅首次包或 LRU 淘汰后的下一包重建 | 单元检查和真实 UDP 数据路径 |
| C3 LRU 原目的地 | TCP accept 后消费；UDP 每个包都携带原目的地，淘汰后在 assignment 前可重建，不再属于不可恢复状态 | UDP 多数据报门禁 |
| C4 空 egress | 删除 v2 空 egress 程序和加载；socket assignment 回复使用正常内核栈 | loader 门禁 |
| C5 legacy map 声明 | 当前自有 loader 仍支持且双编译器/双 verifier 通过；CO-RE 属于后续发行兼容项目，不冒充已完成 | 明确支持边界 |
| E1 UDP 满表静默 | fork 增加 admission callback；两个入口均限频告警且不记录端点/凭据 | rejection 测试 |
| E2 107 配置分歧 | 不在候选尚未完成门禁时修改生产；部署阶段单独校验 | 生产待部署项 |
| E3 remove 后取 Value | immediate/delayed 都保存 item，CAS 后移除 | race 测试 |
| E4 全局锁 | 连接表改为 64 分片；扫描逐片短锁，不再阻塞所有新连接 | 4096 连接并发门禁 |
| E5 提前计数 | grace 连接仅在实际 close 回调时累计 interrupted | 定时确定性测试 |

## 本轮额外发现并修复

- v2 原先丢失 macvlan 逻辑入口 ifindex，会破坏多地区入口归属；现用目的 MAC 到逻辑
  ifindex 的进程内反向 map，并在 close 时清理。
- v2 原先把 DNS 目的地址先按本机地址 bypass，导致 hijack 失效；已恢复和 v1 一致的
  DNS 优先语义，并补齐 DHCP 无条件 bypass。
- 增加 `parse_failures`、`policy_bypass`、`listener_misses` 分阶段计数，避免把“已挂载”
  误判为“数据面可用”。

## 发布边界

VM117 隔离环境通过之前不部署 107/115；生产部署后仍需真实负载与资源趋势门禁。
AF_XDP 不在本轮 TC v2 范围内，不能宣称提升代理加密吞吐。
