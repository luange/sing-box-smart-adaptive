# AdaptivePool 稳定性与能力画像改进说明

完整文档（含验收与发布建议）见：

`/Users/luan/Documents/Codex/2026-07-17/new-chat-3/outputs/adaptive-stability-improvements-20260730.md`

## 摘要

日期：2026-07-30  
工作树：本目录（`a51-beta1-adaptive`）

### 已实现

1. 延迟中位数（最近 10 次）+ 会话隔离的 15% 切换迟滞 + 2m 冷却  
2. 六路径健康隔离加固；DNS 失败加速对应恢复探测  
3. Breaker 指数退避 ±20% jitter  
4. 状态 API：平滑延迟、能力画像、过滤/失败/选择原因  
5. reload retire/close 清理 sticky、audit、selection memory；在途 observation 保留至 epoch 静默  
6. 节点部分可用画像并参与服务路径过滤  

### 审查修正

- sticky 使用 `SessionKey + AffinityID/ServiceID`，不同客户端不串扰。
- `latency` 模式不应用 cooldown/迟滞。
- 状态 API 使用只读 availability，不推进 breaker。
- capability 每条路径保留 `known/available/state`，未知不伪装成已验证可用。
- retire 不清空在途 ObservationIngestor。
- 延迟中位数只采集成功样本；能力过滤不再重复全表扫描吞吐。
- 新切换节点 20 秒内发生高置信失败会立即撤销 sticky 与 lease。
- DNS 恢复任务复用 scheduler `ProbeKey`，pending/running/rerun 自动合并。
- 选择/失败记忆按 `NodeHandle + ServiceID + NetworkPath` 隔离。
- breaker jitter 使用可注入随机源，故障测试可确定复现。
- 状态延迟改为 uint32 毫秒，并从单次只读 HealthStore 快照生成。
- 1000 次 publish/retire 测试结束 live heap 约 2 MiB；真实 Linux SIGHUP RSS 仍需 VM117 验证。

### 配置

```json
"policy": {
  "switch_margin": 0.15,
  "switch_cooldown": "2m"
}
```

### 关键文件

- `protocol/group/adaptive/health.go`
- `protocol/group/adaptive/policy.go`
- `protocol/group/adaptive/node_capability.go`（新）
- `protocol/group/adaptive/outbound.go`
- `protocol/group/adaptive/observation.go`
- `protocol/group/adaptive/switch_audit.go`
- `option/adaptive_pool.go`
- `adapter/adaptive_pool.go`

### 测试

```sh
go test ./protocol/group/adaptive/ ./experimental/clashapi/ ./protocol/group/ -count=1
```

### 约定

之后在本树的任何功能改动，必须同步更新本说明或新增同目录日期 md，并在 `new-chat-3/outputs/` 放完整版。
