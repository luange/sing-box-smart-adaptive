# AdaptivePool / sing-box 交接手册

> **面向**：接手的同事与其它 AI  
> **日期**：2026-07-31  
> **当前生产版本**：`1.14.0-beta.3-reF1nd-luan-adaptive.rc31-probe-hygiene`（生产仍为 rc31/beta.3 核；源码已 port 到 beta.4-reF1nd，待 rc32 CI 出包换核）  
> **状态**：三台生产机（116 / 115 / 107）已部署 rc31，门禁通过  

本文汇总：**产品线决策、源码位置、编译（GitHub）、NAS 备份、部署、监控 API、rc30→rc31 改动、已知债、红线约束**。  
读完应能独立改代码 → CI 出包 → 推 NAS → 换核 → 看运行数据。

---

## 0. 一分钟速览

| 项 | 值 |
|----|-----|
| 产品线 | **reF1nd **v1.14.0-beta.4-reF1nd** + Smart + AdaptivePool**（已从 beta.3 同步到 beta.4-reF1nd，见 §2） |
| 生产核版本 | `1.14.0-beta.3-reF1nd-luan-adaptive.rc31-probe-hygiene` |
| amd64 SHA256 | `c463418d7246ae3354de7d09b4b65ee7907a3aa04cdfd04e4dccfff974f39378` |
| 源码 worktree（Mac） | `/Users/luan/Documents/Codex/2026-06-18/version-3-9-services-sub-store/work/a51-beta4-adaptive` |
| 本地分支 | `rc19-beta4-adaptive` @ `77eecee77` |
| 推送用 GitHub | https://github.com/luange/sing-box-luan-smart |
| GitHub 分支 | `adaptive/rc31-probe-hygiene`（跟踪本地 `rc19-beta4-adaptive`） |
| CI Workflow | `.github/workflows/adaptive-linux-build.yml` → **Adaptive Linux Build** |
| Release | https://github.com/luange/sing-box-luan-smart/releases/tag/adaptive-1.14.0-beta.3-reF1nd-luan-adaptive.rc31-probe-hygiene |
| NAS 核目录 | QNAP：`/share/CACHEDEV1_DATA/Public/sing-box-kernels/`（NFS export `/Public/sing-box-kernels`） |
| 当前 NAS 条目 | `rc31/sing-box-linux-amd64` + `manifest.json` |
| 生产机 | `adaptive-vm116` / `adaptive-vm115` / `adaptive-vm107` |
| **禁止** | Mac 本地 `go build` 占盘；VM 本地多版本 core 备份；未确认就改 nft/PBR/config；Adaptive Go 里写 nft |

---

## 1. 架构与角色

### 1.1 组件

```
Provider 节点目录
    ↓
AdaptivePool (outbound type: adaptive_pool)
    ├─ Catalog / NodeIdentity / EndpointConflict
    ├─ HealthStore + ObservationIngestor（证据 → 健康）
    ├─ ProbeScheduler（HTTP endpoint + DNS/IPv4 coverage）
    ├─ PolicyEngine（选路 / lease / sticky）
    └─ Clash API：/adaptive-pools/v1 + /proxies
```

- **AdaptivePool**：生产选路主路径（地区组 `HK/US/JP/SG/OT`）。  
- **Smart**：历史 outbound；部分机器仍有 `config.last-good.json` / candidate 备份为 smart，**当前 runtime config 是 adaptive_pool**。  
- **仅换核部署**：默认不改 `config.json` / PBR / nft。

### 1.2 生产拓扑

| SSH Host | IP | 角色 | 备注 |
|----------|-----|------|------|
| `adaptive-pve` | 10.20.20.3 | Proxmox | 管理 VM |
| `adaptive-vm116` | 10.30.0.116 | 生产（单 WAN / PBR 实验线） | Alpine，根盘 ~3.2G |
| `adaptive-vm115` | 10.30.0.115 | 生产（Smart→Adaptive 主业务） | Alpine，流量较大 |
| `adaptive-vm107` | 10.20.20.4 | 生产（含 AI 相关出口） | **根盘极小 ~427MB**，注意空间 |
| `adaptive-vm117` | 10.254.40.117 | 隔离测试 / soak（非生产） | 磁盘常满，**不要当编译机** |
| `adaptive-qnap` | 192.168.0.132 | NAS 制品与备份 | |
| `adaptive-builder` | 10.30.0.120 | 曾建 Alpine 编译 VM | **已停用**；日常用 GitHub CI |

密钥：`~/.ssh/id_rsa` 与 `~/.ssh/adaptive_monitor_ed25519`（见 `~/.ssh/config`）。

### 1.3 运行时路径（每台生产机）

| 路径 | 用途 |
|------|------|
| `/root/singbox/sing-box` | 核二进制 |
| `/root/singbox/config.json` | 主配置 |
| `/run/singbox/config.runtime.json` | provider 展开后的 runtime（若存在） |
| OpenRC `singbox` | `rc-service singbox restart` |
| `/var/log/singbox/singbox.err` | stderr 日志（可能很大） |
| Clash API | `http://127.0.0.1:9090`（多数机无 secret） |
| Mixed proxy | `http://127.0.0.1:8888` |

**不要**再依赖 `/root/codex-backups/core-versions/`：rc31 起约定 **备份只在 NAS**，VM 本地 core 备份树已清。

---

## 2. 版本线：已同步到 beta.4-reF1nd

### 2.1 结论（2026-07-31 更新）

- **源码基线**：reF1nd **`v1.14.0-beta.4-reF1nd`**（`1a9ba9269`）。
- **同步方式**：在 beta.4-reF1nd 干净树上，对 `v1.14.0-beta.3-reF1nd..rc31` 的 Adaptive 全量 diff 做 `git apply --3way`，**0 冲突**。
- **Worktree 目录**：已从历史名 `a51-beta1-adaptive` 重命名为 **`a51-beta4-adaptive`**（仅路径名；内容为 beta.4 + Adaptive）。
- **生产核**（写本文时）：三机仍可能运行 **rc31 / beta.3** 二进制，直到 rc32 经 GitHub CI 出包并换核。**不要**把「目录已 beta4」理解成「线上已 beta4」。
- 官方 tag `v1.14.0-beta.4` 与 reF1nd 的 `v1.14.0-beta.4-reF1nd` 对齐使用 **reF1nd 标签**（含 provider/reload 等）。

### 2.2 历史说明（为何曾锁 beta.3）

此前 reF1nd 尚无 beta.4，硬并官方 testing 冲突面大（~127 files），曾 reset 回 beta.3 以保证 rc30/rc31 上线。  
**现 reF1nd 已发 beta.4**，源码线已迁；生产换核单独走 CI + 门禁。

### 2.3 对比（port 时）

| 项 | 值 |
|----|-----|
| 基线 tag | `v1.14.0-beta.4-reF1nd` |
| Adaptive 补丁来源 | `v1.14.0-beta.3-reF1nd..edc011f7a`（约 49 commits / 整树 diff） |
| apply 冲突 | **0** |
| 旧生产分支保留 | `rc18-beta3-adaptive` / `adaptive/rc31-probe-hygiene` |


## 3. 源码与 Git

### 3.1 Worktree

```text
/Users/luan/Documents/Codex/2026-06-18/version-3-9-services-sub-store/work/a51-beta4-adaptive
```

- 分支：`rc19-beta4-adaptive`  
- HEAD：`77eecee77`  
- 跟踪：`luan/adaptive/rc31-probe-hygiene`  
- Adaptive 主代码：`protocol/group/adaptive/`  
- Clash API：`experimental/clashapi/adaptive_pool.go`、`proxies.go`（挂载 `/adaptive-pools/v1`）  
- 接口：`adapter/adaptive_pool.go`

### 3.2 Remotes

| remote | URL | 用途 |
|--------|-----|------|
| `origin` | https://github.com/reF1nd/sing-box.git | 上游 reF1nd（**无写权限预期**） |
| `upstream` | https://github.com/SagerNet/sing-box.git | 官方 |
| `luan` | https://github.com/luange/sing-box-luan-smart.git | **我们推送 / CI / Release** |

```bash
cd /Users/luan/Documents/Codex/2026-06-18/version-3-9-services-sub-store/work/a51-beta4-adaptive
git remote -v
git status -sb
```

### 3.3 关键提交

| Commit | 说明 |
|--------|------|
| `9b574ae35` | rc30：生产反馈收口 + health evidence 硬化 |
| `c4235a301` | rc31：AF0 framing / replica 探针与选路 + CI workflow |
| `77eecee77` | rc31：修 replica score 单测断言 |

### 3.4 Build tags

`release/DEFAULT_BUILD_TAGS_OTHERS`（与生产一致，含 clash_api、gvisor、wireguard 等）。  
ldflags：`release/LDFLAGS` + `-X github.com/sagernet/sing-box/constant.Version=...`

---

## 4. 编译：只用 GitHub Actions（不要用 Mac）

### 4.1 原因

- Mac 根分区紧张；本地交叉编译曾把 `~/Library/Caches/go-build` 撑到 **~20GB**。  
- 约定：**Mac 不 `go build`**；编译在 `luange/sing-box-luan-smart` 的 Actions。

### 4.2 Workflow

文件：`.github/workflows/adaptive-linux-build.yml`  
名称：**Adaptive Linux Build**

触发：

1. `push` 到 `adaptive/**` 或 `rc*-beta3-adaptive`（相关路径变更）  
2. `workflow_dispatch`（可勾选测试 / 发 Release）

产物：

- `sing-box-linux-amd64` / `arm64`  
- `.sha256` / `.tar.gz`  
- `BUILD-INFO.md`  
- 可选 GitHub Pre-release：`adaptive-<version>`

### 4.3 手动触发

```bash
gh workflow run adaptive-linux-build.yml \
  -R luange/sing-box-luan-smart \
  --ref adaptive/rc31-probe-hygiene \
  -f version='1.14.0-beta.3-reF1nd-luan-adaptive.rc32-your-slug' \
  -f run_tests=true \
  -f publish_release=true

gh run watch -R luange/sing-box-luan-smart
gh release list -R luange/sing-box-luan-smart --limit 5
```

### 4.4 本地只改代码时

```bash
cd .../a51-beta4-adaptive
# 改 protocol/group/adaptive/...
git add -A && git commit -m "..."
git push luan HEAD:adaptive/rc31-probe-hygiene   # 或新分支 adaptive/rc32-...
# 等 CI；不要在 Mac 上 go build
```

### 4.5 备用编译机（非默认）

- PVE VMID **120** `singbox-builder`，IP `10.30.0.120`，SSH `adaptive-builder`  
- 24G 盘、4C/4G，曾注入 net/ssh；**已 shutdown**  
- 仅当 GitHub 不可用时再启用；用完关机  

VM117 **磁盘常 100%**，只做故障注入，**禁止**当编译机。

---

## 5. NAS 制品（唯一长期备份）

### 5.1 路径

| 访问 | 路径 |
|------|------|
| QNAP SSH | `/share/CACHEDEV1_DATA/Public/sing-box-kernels/` |
| NFS export | `192.168.0.132:/Public/sing-box-kernels` |
| Mac NFS 挂载（若已挂） | `/Users/luan/NFS/Public/sing-box-kernels`（可能只读） |

结构示例：

```text
sing-box-kernels/
  manifest.json
  rc19/
  rc22/
  rc31/
    sing-box-linux-amd64
```

### 5.2 manifest.json 字段约定

```json
{
  "schema": 1,
  "current": "<version>",
  "previous": "<old version or null>",
  "versions": {
    "<version>": {
      "source_commit": "<short sha>",
      "source": "https://github.com/luange/sing-box-luan-smart",
      "release_tag": "adaptive-<version>",
      "amd64": {
        "file": "rc31/sing-box-linux-amd64",
        "sha256": "<hex>"
      }
    }
  }
}
```

### 5.3 从 GitHub 发布到 NAS

```bash
TAG=adaptive-1.14.0-beta.3-reF1nd-luan-adaptive.rc31-probe-hygiene
WORKDIR=$(mktemp -d /tmp/adaptive-rel.XXXXXX)
cd "$WORKDIR"
gh release download "$TAG" -R luange/sing-box-luan-smart -p 'sing-box-linux-amd64*' 
shasum -a 256 -c sing-box-linux-amd64.sha256

ssh adaptive-qnap 'mkdir -p /share/CACHEDEV1_DATA/Public/sing-box-kernels/rc31'
scp sing-box-linux-amd64 adaptive-qnap:/share/CACHEDEV1_DATA/Public/sing-box-kernels/rc31/
# 再更新 manifest.json（jq 或手工）
rm -rf "$WORKDIR"   # 勿长期留在 Mac
```

生产机也可：`pull_adaptive_core_from_nas.sh`（NFS mount 只读拉核）。  
脚本：`outputs/pull_adaptive_core_from_nas.sh`。

---

## 6. 部署

### 6.1 原则

1. **顺序**：116 → 115 → 107（先边缘后核心/AI）  
2. **仅换核**，默认不改 config / nft / PBR  
3. **备份 = NAS**；VM 不保留多版本 `core-versions` 树  
4. 门禁：version/sha 匹配 + adaptive pools generation/candidates + `generate_204` + youtube  

### 6.2 历史脚本

- `outputs/deploy_singbox_core_atomic.sh`  
  - 参数：`BINARY SHA256 VERSION HOST [HOST ...]`  
  - 旧逻辑会在 `/root/codex-backups/core-versions` 留两份核 → **与当前“只 NAS 备份”冲突**；107 小盘易炸。  
  - 接手应改脚本：**去掉或可选关闭 VM 本地备份**，或继续用 rc31 手写流程（见下）。

### 6.3 rc31 实际使用的部署要点（推荐）

```bash
# 在临时目录准备好 BIN / SHA / VER 后：
scp "$BIN" "$HOST:/root/sing-box.candidate"
ssh "$HOST" sh -s -- "$SHA" "$VER" <<'REMOTE'
set -eu
STAGED=/root/sing-box.candidate
TARGET=/root/singbox/sing-box
# verify sha + version + check -c config
# 可选：rm -rf /root/codex-backups/core-versions
mv -f "$TARGET" "$TARGET.prev"   # 单文件回滚句柄
install -m 0755 "$STAGED" "$TARGET.new"
mv -f "$TARGET.new" "$TARGET"
rc-service singbox restart
# wait API /adaptive-pools + curl -x 8888 google/youtube
# 成功后 rm -f "$TARGET.prev"
REMOTE
```

### 6.4 回滚

1. **优先**：NAS `manifest.json` 的 `previous` / 历史 `rcXX/` + GitHub 旧 Release  
2. 临时：若仍有 `$TARGET.prev` 且未删  
3. **不要**指望 VM 上 `codex-backups/core-versions`（rc31 后应已清空）

### 6.5 rc31 部署结果（2026-07-31）

| 主机 | 结果 | 备注 |
|------|------|------|
| 116 | passed | Google 204 / YouTube 200 |
| 115 | passed | 同上 |
| 107 | passed | 同上；清了本地 core 备份后空间仍紧 |

报告：`outputs/adaptive-rc31-deploy-20260731.md`

---

## 7. 监控与 API

### 7.1 正确入口

| URL | 说明 |
|-----|------|
| `GET /version` | 核版本 |
| `GET /adaptive-pools/v1` | 全部 pool 状态（**正确路径**；`/adaptive` 是 404） |
| `GET /adaptive-pools/v1/{tag}/status` | 单 pool |
| `GET /proxies` | Clash 兼容；Adaptive 组带 `adaptive_pool` 字段 |
| `GET /connections` | 当前连接 |

### 7.2 关键指标（pool 标量）

| 字段 | 含义 | 告警倾向 |
|------|------|----------|
| `probe_queue_depth` | 探针队列深度 | OT 曾 >100 → 调度跟不上 |
| `candidate_count` | 候选数 | OT ~71 最大 |
| `active_leases` | 会话租约 | 过高 + lease_evictions 抖 |
| `selection_switches_total` | 切换次数 | 与 thrash 相关 |
| `business_tls_failures_total` | 业务 TLS 失败 | rc30 常为 0（观测偏哑） |
| `transport_failures_total` | 传输失败 | |
| `endpoint_conflict_count` | 同 endpoint 多凭证 | 与 `(2)` 副本相关 |
| `candidates[].health` | healthy / unreachable / … | |
| `candidates[].filter_reason` | 过滤原因 | |
| `paths[]` | tcp/ipv4、udp_dns/ipv4 等 | v6 多为 unknown（预期） |

### 7.3 抽样命令

```bash
ssh adaptive-vm115 'curl -fsS http://127.0.0.1:9090/version'
ssh adaptive-vm115 'curl -fsS http://127.0.0.1:9090/adaptive-pools/v1' -o /dev/shm/ap.json
# 有 python3 的机器可 jq/python 摘要 probe_queue / health 直方图
```

注意：116 的 `/tmp` tmpfs 易满（曾 100%）；大 JSON 写 **`/dev/shm`**，不要写 `/tmp`。

---

## 8. rc30 → rc31 代码改动（必须读）

### 8.1 问题（rc30 生产观测）

1. **`udp_dns/ipv4: unknown address family: 0`**（及 `unknown version`）大量出现在 `last_failure`，把节点打成 **unreachable**（污染健康）。  
2. **OT `probe_queue_depth` ~130+**，探针堆满。  
3. Provider **`(2)` 副本** TLS “first record does not look like a TLS handshake” 成片 Unreachable，仍占探针与选路。  
4. Mac 本地编译占盘；VM 本地多核备份挤爆小盘（107）。

### 8.2 修复（commit `c4235a301`）

| 文件 | 改动 |
|------|------|
| `protocol/group/adaptive/probe_runtime.go` | framing → **`ConfidenceLow`**（metrics-only，weight&lt;0.5，不累计 NonBreaker→Unreachable）；`isProviderReplicaTag` / `isProviderReplicaCandidate`；startup **跳过 replica 的 DNS 自动探针**，endpoint 探针延后 |
| `protocol/group/adaptive/policy.go` | replica 选路 **+8s** 等效 delay；endpoint_conflict 非 replica **+2s** |
| `protocol/group/adaptive/dns_health_test.go` | framing 不致 Unreachable；replica tag 检测 |
| `protocol/group/adaptive/probe_startup_test.go` | replica 无 DNS task |
| `protocol/group/adaptive/policy_test.go` | 选路降权测试 |
| `.github/workflows/adaptive-linux-build.yml` | CI 编译/发版 |

### 8.3 关键机制说明（给 AI）

- `confidencePolicy(ConfidenceMedium)` → weight **0.60** → `observeQuality` **会**在失败累计后标 Unreachable。  
- `ConfidenceLow` → weight **0.25** → **metricsOnly**，只记数不改 Health 枚举。  
- 因此 framing 必须 Low，不能 Medium。  
- replica 判定：tag 以 ` (N)` 结尾且 N≠1（如 `… NeaRoute-2 (2)`）。

### 8.4 未修 / 仍债（下一任优先）

| 优先级 | 项 | 说明 |
|--------|-----|------|
| P1 | 业务 TLS 观测仍偏哑 | `business_tls_failures_total` 常 0，切换偏探针 |
| P1 | 115 HK：DNS healthy 多、TCP healthy 少 | 健康维度与真实 TCP 不完全一致 |
| P1 | lease thrash | 115 HK switches/lease_evict 曾偏高 |
| P2 | IPv6 path 全 unknown 仍占状态 | 可 IPv4-only 池不建 v6 ledger |
| P2 | OT 候选 71 仍大 | rc31 已减 replica DNS；可再 cap coverage |
| P2 | 107 根盘 ~128MB 可用 | 日志轮转 / 勿在盘上堆二进制 |
| P3 | beta.4 port | 等 reF1nd 或单独立项 |

---

## 9. 配置约定（Adaptive 组）

生产 config 中 outbound 示例类型：

```json
{
  "type": "adaptive_pool",
  "tag": "HK",
  "use_all_providers": true,
  "include": [ "..." ],
  "exclude": [ "..." ],
  "probe": { },
  "policy": { },
  "capability": { },
  "shadow": false
}
```

- `shadow: true`：只观测不进业务（灰度用；VM117 场景）。  
- 地区组常见 tag：`HK` `US` `JP` `SG` `OT`；上层 `select` selector 默认 HK 等。  
- **改 config 需单独评审**；换核脚本默认不动 config。

---

## 10. 测试

### 10.1 CI 已跑

```text
go test -count=1 -timeout 15m -tags "$BUILD_TAGS" ./protocol/group/adaptive/...
```

在 Adaptive Linux Build 的 amd64 job。

### 10.2 关键单测（rc31）

- `TestProxyFramingProbeErrorClassification`  
- `TestProxyFramingDNSHealthDoesNotMarkUnreachable`  
- `TestProviderReplicaTagDetection`  
- `TestStartupProbeTasksSkipDNSForReplicaTags`  
- `TestCandidateScoreDeprioritizesProviderReplica`  

### 10.3 生产门禁（最低）

1. `sing-box version` 与 SHA 匹配  
2. 各 adaptive_pool `generation>0 && candidate_count>0`  
3. `curl -x http://127.0.0.1:8888 -o /dev/null -w '%{http_code}' https://www.google.com/generate_204` → 204  
4. 同理 youtube → 200  
5. errlog 无 panic/fatal  

---

## 11. 运维红线（给 AI 的硬约束）

1. **不要**在用户 Mac 上 `go build` / 堆 `go-build` cache。  
2. **不要**未确认就改 nft、PBR、生产 `config.json`。  
3. **不要**在 Adaptive Go 代码路径实现 nft。  
4. **不要**默认在 VM 上保留多份 core 备份（107 盘不够）。  
5. **不要**把官方 beta.4 / testing  bulk merge 进生产分支。  
6. 部署顺序 **116 → 115 → 107**；先门禁再下一台。  
7. 大 JSON 监控写 **`/dev/shm`**，勿写满 `/tmp`。  
8. 二进制临时下载用完 **删掉**；长期只留 NAS + GitHub Release。

---

## 12. 建议接手工作流

```text
1. 读本文 + adaptive-rc31-deploy-20260731.md
2. ssh 三台确认 version/sha = rc31
3. 拉 /adaptive-pools/v1 看 probe_queue / health 是否改善
4. 改代码只在 a51 worktree 的 protocol/group/adaptive
5. git push luan → 等 Adaptive Linux Build → Release
6. gh release download → scp NAS rcXX/ → 更新 manifest
7. 换核 116→115→107 + 门禁
8. 更新本文「当前生产版本」表与 deploy 报告
```

---

## 13. 相关文件索引

| 路径 | 说明 |
|------|------|
| 本文 | `.../outputs/ADAPTIVE-POOL-HANDOFF.md` |
| rc31 部署短报 | `.../outputs/adaptive-rc31-deploy-20260731.md` |
| rc30 部署短报 | `.../outputs/adaptive-rc30-deploy-20260731.md` |
| 原子部署脚本（旧，含 VM 备份） | `.../outputs/deploy_singbox_core_atomic.sh` |
| NAS 拉取脚本 | `.../outputs/pull_adaptive_core_from_nas.sh` |
| Desktop rc30 包（历史） | `~/Desktop/sing-box-adaptive-beta3-rc30-smart-closeout/` |
| 知识库目录 | `Documents/Codex/KNOWLEDGE-BASE/30-projects/proxy-singbox/` |
| CI | `.github/workflows/adaptive-linux-build.yml` |
| Adaptive 实现 | `protocol/group/adaptive/*.go` |

---

## 14. 当前生产指纹（验收用）

```text
version: 1.14.0-beta.3-reF1nd-luan-adaptive.rc31-probe-hygiene
sha256:  c463418d7246ae3354de7d09b4b65ee7907a3aa04cdfd04e4dccfff974f39378
commit:  77eecee77
hosts:   adaptive-vm116, adaptive-vm115, adaptive-vm107  (all match)
nas:     .../sing-box-kernels/rc31/sing-box-linux-amd64
release: adaptive-1.14.0-beta.3-reF1nd-luan-adaptive.rc31-probe-hygiene
```

验收命令：

```bash
for h in adaptive-vm116 adaptive-vm115 adaptive-vm107; do
  echo "==== $h ===="
  ssh "$h" '/root/singbox/sing-box version | head -1; sha256sum /root/singbox/sing-box'
done
```

---

## 15. 变更日志（交接窗口）

| 日期 | 事件 |
|------|------|
| 2026-07-31 | rc30 smart-closeout 上线三机；产品线确认 beta.3 only |
| 2026-07-31 | 说明不可用 beta.4 的结构差距；清理 Mac go-build cache |
| 2026-07-31 | 运行观测：AF0 / probe queue / (2) 副本问题 |
| 2026-07-31 | 代码修复 + GitHub Actions CI；Release rc31 |
| 2026-07-31 | NAS 发布；116→115→107 换核成功；VM 本地 core 备份清除 |
| 2026-07-31 | 本文交接手册 |

---

*维护：有生产换核或重大决策时，请同步更新 §0 速览表、§14 指纹与 §15 日志。*
| 2026-07-31 | worktree 重命名 a51-beta4-adaptive；源码同步到 v1.14.0-beta.4-reF1nd（rc19-beta4-adaptive） |
