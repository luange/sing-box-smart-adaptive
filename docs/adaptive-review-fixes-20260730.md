# Adaptive 审查点修复（专业审查 + PM 口径）

日期：2026-07-30
工作树：`a51-beta1-adaptive`

## 修复项

### 1. `tcp/any` / `udp/any` 误杀（P0）

**问题：** 单族已知坏 + 另一族未知时，聚合路径可能返回 Known+Unavailable。
**修复：** `aggregateDualStackCapability`：

- 任一已知可用 → 可用
- **仅当两族都已知且都不可用** → 不可用
- 单坏 + 未知 → fail-open（Available=true, Known=false）

文件：`protocol/group/adaptive/node_capability.go`
测试：`TestDualStackAnyFailsOpenWhenOneFamilyUnknown`

### 2. `ReadFrom` 真实写失败归因（P0）

**问题：** `ReaderFrom.ReadFrom` 错误可能来自上游 body/file，却记成节点 TLS/写失败。
**修复：** 仅当 `isNodeNetworkIOError(err)`（OpError/DNS/timeout/ECONNRESET/EPIPE/…）才调用 `observeWriteFailure`。

文件：`protocol/group/adaptive/business_observation.go`
测试：`TestReadFromLocalReaderErrorsDoNotPenalizeNode`

### 3. AI 服务可用性封存（P0）

**问题：** `builtin_ai_service_tls` 仍可配置启用。
**修复：**

- `AdaptivePool.New`：**拒绝** `BuiltinAIServiceTLS=true`
- `NewBuiltinCapabilityTargetProvider(..., includeAI=true)`：返回 sealed 错误
- 字段保留 JSON 兼容 + 注释标明 sealed
- YouTube TLS / exit identity / signed manifest 仍可用
- 配置文档中英文更新

测试：`TestAdaptivePoolBuiltinAIServiceCapabilityIsSealed`
（`NewBuiltinAIServiceTLSTargetProvider` 仍供单元表驱动测试，不经配置入口）

### 4. 发布脚本 PASS 顺序

`run-adaptive-release-gates.sh`：unit → race → **heap** → related → vet → **最后才 PASS**。

### 5. 文档 trailing whitespace

清理 `docs/**/*.md` 与相关 outputs md 行尾空白，满足 `git diff --check`。

## 产品方向对齐

- Smart 核心：节点可用性、真实失败学习、租约、切换审计、权重/过滤
- 服务可用性探测：封存，等协议+认证模型
- v4/v6、TCP、DNS-UDP、Data-UDP 分轨；未知 fail-open

## 验证

```sh
cd a51-beta1-adaptive
go test ./protocol/group/adaptive/ -count=1
go test -race ./protocol/group/adaptive/ -count=1 -timeout 10m
go vet ./protocol/group/adaptive ./option ./adapter
./scripts/run-adaptive-release-gates.sh
```
