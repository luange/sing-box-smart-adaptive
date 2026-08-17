# Changelog（adaptive 增量）

只记录相对 **SagerNet 官方 tag** 的本仓库变更。上游 changelog 见 `docs/changelog.md`。

---

## 1.14.0-beta.17-official-smart-ebpf-perf — 2026-08-18

### 性能 / PBR 网关

- eBPF / shared-network **连接级日志** Info → Debug，避免网关刷盘
- **bypass miss 抽样**：对照静态 LPM；`kernel_miss` 告警；DIRECT 漏表 **gap_heal** `/32` promote
- `dns_prefill` 成功 promote 改 Debug；运行时指标保留
- Smart 探测去掉强制 `runtime.GC()`；冷启动探测默认 cap **45s**
- 脚本：`scripts/bypass-miss-sample.sh`

### 自洽 / HA（同周期）

- ConnectionManager 接通 **VerdictLearner + ConnectionSplicer**（此前注册未调用）
- **VerdictLearnerHub / ConnectionSplicerHub** 多 inbound fan-out
- Mixed shared-network learn 门控与 inbound 一致；`invoked` / `non_direct` 可观测
- Smart/selector/urltest/loadbalance/adaptive **NoteRealOutbound**；history **FinalizeChain** 记叶子
- Smart Close 有界等待，避免 `sing-box did not close!`
- Provider 重复 tag **内容稳定** `#`+hex 后缀
- Clash `GET /history` 根路径 → status

### 策略说明

- **不**合并 reF1nd 整树；纯官方 beta.17 + 自有端口
- AdaptivePool 继续 **PreMatchDisabled**（lease/观测语义）
- PBR 下 dial learn `writes≈0` 为预期（直连在 TC）

---

## 1.14.0-beta.17-official-smart-ebpf — 2026-08-17

### 基底

- 官方 `v1.14.0-beta.17` 干净树
- 注册：ProviderManager、ProviderOptionsRegistry、smart/eBPF/loadbalance/pass/history

### 功能端口

- Smart + AdaptivePool + eBPF DirectOffload（route + prefill + learn）
- DNSAnswerObserverHub / DirectOffloadHub
- MatchInputs 作用域 + RuleSet MatchClass
- connection_history + Clash `/history/*`
- loadbalance / pass

### 修复

- netlink Route.Src `*IPNet`
- provider 429 / NetworkList / anytls TFO 清理
- pre_match 测试恢复

---

## 更早线（摘要）

| 标签/线 | 备注 |
|---------|------|
| beta.14 / beta.15 smart-direct | 早期 DIRECT offload / mem 实验 |
| reF1nd overlay 尝试 | **已放弃**；改官方纯基底 |

---

## 升级提示（运维）

1. 二进制 tags 需含 `with_ebpf` + `with_connection_history`（完整网关）  
2. 生产建议：`log.level=info`（连接明细已在 Debug）  
3. Smart：`probe_interval` 30m+、`dns_prefill.ttl` 10m、history retention 可 72h  
4. 自检：`grep 'bypass miss sample' …`；`sh scripts/bypass-miss-sample.sh`  
