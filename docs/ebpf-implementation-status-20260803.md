# eBPF In/Out 落地状态（2026-08-04）— rc49-dae-maturity + closeout lab

合同：`docs/ebpf-in-out-framework-master-20260803.md`  
审核整改：`docs/framework-requirements-boundaries-20260804.md`  
代码审核方向：`docs/ebpf-code-review-directions-20260804.md`（Q1–Q14）  
整改实施指南：`docs/ebpf-remediation-guide-20260804.md`（N1–N10 + Q3/Q5）  
剩余清单：`docs/ebpf-remaining-work-20260804.md`

## 总览

| 模块 | 状态 | 证据 |
|---|---|---|
| IN-FIX-1/2 | ✅ | LRU redirect_map |
| OUT-B splice v4/v6 | ✅ | W2 lab + iperf |
| OUT-A F-5 v4 | ✅ | rc45c-f5 |
| OUT-A IPv6 verdict | ✅ | W1 lab：`[240e:ff:30::3]:18080` writes=1 kernel_hits=150 HTTP 200/200；ULA 本机旁路属预期 |
| Q1–Q2 / Q4 / Q6–Q14 | ✅ | 含 N1–N10 复核补丁 |
| Q3 P1–P4 | ✅ | RouteMatchInputs + 全 item MatchClass + sniff-on IP-only learn + allow_with_sniff deprecate |
| Q5 step1 | ✅ | 删除 2s liveTick；accounting 路径字节 idle 保留 |
| Q5 step2–4 | ✅ | backend 级单 epoll + idle 清扫；失败 per-pair fallback |
| W6 C.2 | ✅ 关闭 | feasibility doc |
| lab 默认 | ✅ | `verdict.mode=off` |

## 二进制（112）

- 版本：`rc49-dae-maturity`（PVE `/tmp/sing-box-rc49`，tags `with_ebpf`）
- 路径：112 `/root/singbox/sing-box`（部署时备份 prev）
- PVE：`go test -race -tags with_ebpf ./common/ebpf ./protocol/ebpf ./route/rule` 绿

## 本轮（remediation-guide N + 续作）

| # | 项 | 处理 |
|---|---|---|
| N1 | 指纹先提交 | 仅 `InvalidateAll` **成功后**提交指纹；失败可重试 |
| N2 | rule-set / refreshErr | `updated` → `InvalidateVerdictNow`；`refreshErr` → 强制作废；`NoteBypassFingerprint` 基线 |
| N3 | max_pairs 启动错误 | 统一 clamp+Warn；`max_pairs:8` 可启动；0 保留默认语义 |
| N4 | walkConnChain | 深度截断返回 false；三调用方 refuse |
| N5 | skip 原因 | `resolveLearnDestination` 返回 reason；去掉 peer-only 兜底 |
| N6 | 死代码注释 | 删节流谎报；export 单环形 |
| N7 | fingerprintSeeded | 显式 bool，不用空串哨兵 |
| N8 | splice metrics err | Warn 一次（节流字段） |
| N10 | 单测 | invalidate / conn_chain / export ring / capacity clamp / route inputs |
| Q3 P1 | MatchInputs | adapter 位掩码 + matchInner 累加 + learn 门 AND 旧 sniff 门 |
| Q5 s1 | liveTick | 删除 2s TCP_INFO 轮询 |

## 配置（lab 默认安全）

```json
"outbound_offload": {
  "splice": { "enabled": true, "accounting": true, "half_close": "close" },
  "verdict": { "mode": "off" }
}
```

## 明确未完成 / 冻结

| 项 | 说明 |
|---|---|
| C.3 UDP offload | 冻结 |
| 116 内核 | 不改；splice fail-open |
| DNS prefill | **明确不做**（保 DNS 灵活性） |
| 全量 TC 规则引擎 | 不做 |
| Q5 step4 500-conn pprof | 可选加深；已有 single-epoll 启动证据 + splice pair active |

## Closeout lab（2026-08-03）

| 项 | 结果 |
|---|---|
| Phase 0 L0/L3/L4 | 见 `docs/ebpf-vs-dae-perf-gap-20260804.md` |
| W1 v6 F-5 | kernel_hits=150，200/200，恢复 off |
| W0/v4 learn（Q3） | kernel_hits=49，无需 allow_with_sniff |
| 112 默认 | `verdict.mode=off`，splice on + backend watcher |

## 本轮（rc49-dae-maturity）

| 项 | 处理 |
|---|---|
| Q3 P2/P3 | `route/rule/rule_item_match_class.go` 全 item + RuleSet 元数据 |
| Q3 P4 | `allow_with_sniff` deprecate warn；MatchInputs 权威门 |
| Q3 learn+sniff | MatchInputs≠0 且 IP-only 时忽略 sniff Protocol 启发式 |
| Q5 step2–3 | `splice_watcher.go` 单 epoll + idle 清扫；Release 先 DEL 再 close |
| 产品 | Linux-first；不做独立 `type: ebpf` out |
| 单测 | route/rule MatchClass + protocol/ebpf verdict 门 PVE 绿 |
