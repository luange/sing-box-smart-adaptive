# Changelog（adaptive 增量）

只记录相对 **SagerNet 官方 tag** 的本仓库变更。上游 changelog 见 `docs/changelog.md`。

## Unreleased — Smart probe/profile stability

- Share Smart probe admission across credential variants that describe the
  same provider endpoint; credentials remain excluded from the identity while
  endpoint address, port, TLS and transport stay part of the profile key.
- Preserve a bounded probe worker default for embedded/test constructors so a
  zero-value concurrency setting cannot silently disable all health checks.
- Add regression coverage for endpoint identity separation and credential
  rotation.

---

## 1.14.0-rc.1-official-smart-ebpf-v3.13-stream-recovery — 2026-08-26

- Wake the existing shared 204 recovery probe when an established Smart TCP
  stream reports a timeout, reset, broken pipe, or network-unreachable error.
- Do not directly penalize a node from a single stream error; ordinary EOF,
  local close, and cancellation remain neutral.
- Coalesce repeated errors from the same stream and add focused race-tested
  regression coverage.

## 1.14.0-rc.1-official-smart-ebpf-v3.12-recovery — 2026-08-26

- Wake one coalesced background recovery probe immediately after a real TCP
  dial failure, UDP setup failure, or response-expected UDP flow timeout.
- Keep same-request candidate failover on the data plane; recovery no longer
  depends on opening a dashboard or manually running a latency test.
- Add focused and race-tested regression coverage for failure wake-up and
  burst coalescing.

## 1.14.0-rc.1-official-smart-ebpf-v3.9-ingress-route — 2026-08-24

- Added `route.rules[].inbound_interface` so transparent PBR gateways route by
  the actual eBPF ingress interface instead of the unchanged client source IP.
- This permits a direct `eth0/pa-us/pa-jp/pa-sg/pa-other` to
  `HK/US/JP/SG/OT` mapping without SNAT or duplicated client subnets.

## 1.14.0-rc.1-official-smart-ebpf-v3.1 — 2026-08-21

### Official baseline

- Rebased the complete first-party Smart/eBPF/provider stack onto SagerNet
  official `testing` commit `712046a26` (`1.14.0-rc.1` snapshot).
- Adapted custom network listeners to the official asynchronous
  `InterfaceUpdated(context.Context)` lifecycle.

### Reproducibility and teardown

- Added the previously builder-only eBPF v3 control plane, TC program, runtime,
  static-rule sink, tests, and design document to Git; a clean clone is now
  sufficient to build v3.
- Continue route, backend and listener cleanup even when a TC detach reports an
  error; retained attachments remain retryable on a later close.
- Serialize live kernel generation synchronization with v3 flow/DNS/reload and
  close operations.
- Make `RouteMatchUnknown` a real bit so unknown rule classes fail closed rather
  than disappearing during bitwise accumulation.
- Preserve the outbound manager map/list invariant on failed removal.

### Build and validation

- GitHub release workflow builds four eBPF binaries: amd64/arm64 × glibc/musl.
- Linux `with_ebpf` tests, race, vet, and five repeated kernel data-path/load/
  policy-route collision gates pass before release.

---

## 1.14.0-beta.17-official-smart-ebpf-v3-profilefix.6 — 2026-08-21

### Smart cold-start availability

- Commit completed probe observations even when a bounded probe cycle reaches its deadline.
- Trigger one coalesced probe immediately after a provider publishes candidates; idle groups no longer wait for the periodic interval to build profiles.
- Publish the first successful basic probe while the rest of the group continues in the background, removing the cold-start request stall.
- Keep a candidate eligible after one or two basic-probe failures; isolate it only after three consecutive failures. Real traffic failures still feed the shared profile immediately.
- Publish probe-only profiles to the Clash API even when a region has no business traffic.
- Fix the confirmed-dead lookup to use the complete shared probe key before interrupting existing connections.

### Lifecycle and observability

- Make provider-owned outbound removal idempotent and remove the remaining invalid-index panic path.
- Close providers before the outbound manager so provider children can unregister safely.
- Treat normal fail-open proxy handoff as informational rather than an eBPF warning.

### Validation

- `go test`, `go test -race`, and `go vet` pass for the affected Smart/eBPF/outbound packages.
- VM115 cold-start gate: Google 204, Google Search, YouTube, and Cloudflare 204 succeeded from the macOS PBR path.

---

## eBPF data-plane v3 polish — 2026-08-21

Design: `docs/ports/EBPF-DATAPLANE-V3-DESIGN.md`. QA: Codex outputs `EBPF-V3-117-CANARY-QA-*.md`.

### Architecture (control plane = one sink)

- **Unified publisher**: `Lifecycle` + `DataplaneSink` dual-write memory model and kernel maps (no silent dual-brain).
- **DNS/prefill → v3**: `promoteLearnedBypass` also `PublishDNSHint` + `MergeStaticDirect` (active bank, no gen bump).
- **Static snapshot**: full `PublishStaticDirect` deletes removed LPM keys on inactive bank before commit.
- **Flow keys**: reverse published with `direction=0` + swapped 5-tuple (matches TC lookup).
- **Fragments**: never first-packet DIRECT; NEED_USERSPACE / parse-fail path.
- **PA default**: `capture_local` defaults **false** when `shared_network.enabled` (explicit true still allowed).
- **Interface reload**: one generation commit via static republish (no triple-bump).

### Canary

- 117: kernel `sb_v3_ingress` load OK after verifier fixes; soak with `capture_local=false`.
- 117 validated the isolated canary before staged VM115 deployment.

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
