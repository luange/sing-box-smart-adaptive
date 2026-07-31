# AdaptivePool 稳定性与能力画像改进说明

完整文档：

`/Users/luan/Documents/Codex/2026-07-17/new-chat-3/outputs/adaptive-stability-improvements-20260730.md`

## 摘要（2026-07-30 修订）

### 已实现

1. 成功延迟中位数（10 样本）+ 15% 迟滞 + 2m 冷却（仅 adaptive）
2. Sticky 键 = `Session + Affinity/Service`（不跨客户端）；`affinity_mode=disabled` 可关
3. 六路径隔离；DNS 失败加速恢复探测
4. Breaker 指数退避 ±20% jitter（可注入随机源）
5. Plan/状态只读可用性（不改 breaker）
6. capability：`known` / `available` / `state`（unknown ≠ verified）；单 map 入口 + 低于 quorum 软反馈
7. `filter_reasons` 多路径；`service_memories` 按服务
8. retire 清 sticky/audit/memory，**不清** ObservationIngestor
9. UDP 成功写 transport 路径；DNS 需 QR 形（非 QR 不写 service）；ListenPacket 不写 High success
10. 超时统一 medium；累计达 threshold → HealthUnreachable 退场（非单次 hard open）
11. DomainPermit 与 Status 同键解析（含 */any→族）；Low conf 不改 Health
12. rank 在族无样本时回退 aggregate 账本；permit busy 仍质量学习
13. **收口（生产对照）**：删 capability below-quorum soft；DNS 自动探针仅 IPv4；
    代理封装错误（address family 0 / unknown version）→ medium 不硬开闸；
    拨号族钉扎忽略私网 RemoteAddr，优先 destination/FakeIP
14. **健壮性**：quality Unreachable 可被 medium+ 成功恢复并清 NBF；证据 At/permit
    统一 HealthStore.Now()；errorReason 单行截断；epoch 交接测试抗 coalesce

### 配置

```json
"policy": {
  "switch_margin": 0.15,
  "switch_cooldown": "2m",
  "affinity_mode": "service"
}
```

- `switch_cooldown`：`0`/省略=默认 2m；**负数=关闭**；正数=显式时长
- `switch_margin`：省略=0.15；显式 `0`=关闭比例迟滞
- `affinity_mode`：省略/`service`=按产品 sticky；`disabled`=关闭 sticky（租约仍生效）

### 测试

```sh
go test ./protocol/group/adaptive/ ./experimental/clashapi/ ./protocol/group/ -count=1
```

### 结构 / 性能（同日后续）

详见：`Documents/Codex/2026-07-17/new-chat-3/outputs/adaptive-structure-perf-20260730.md`

- `outbound.go` 拆为 `status_export` / `selection_memory` / `probe_runtime`
- Plan 热路径：`RequiredPathKnownBlocked`，避免每候选全量 7 路径画像
- Status：路径行不再每 path 全量 `candidateScore`；`PeekAvailable` 只读契约

### 约定

本树任何改动必须同步更新本文件与 `new-chat-3/outputs` 完整版 md。
