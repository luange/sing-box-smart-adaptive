# eBPF In/Out 整改实施指南（2026-08-04）— 复核 rc47-qfix + 逐项到行改法

上游文档（读这份之前必须已读）：

| 文档 | 作用 |
|---|---|
| `docs/ebpf-in-out-framework-master-20260803.md` | 总合同（模块边界、F-1..F-5） |
| `docs/framework-requirements-boundaries-20260804.md` | 需求与硬边界（§4 是红线） |
| `docs/ebpf-code-review-directions-20260804.md` | 上一轮代码审核方向（Q1–Q14） |
| `docs/ebpf-remaining-work-20260804.md` | 功能开工单（W0–W7） |
| 本文 | **复核 rc47-qfix 的 Q 落地质量 + 到行级整改指令**（N1–N10）+ Q3/Q5 完整落地方案 |

本文的存在理由：上一轮我只给了「方向」，grok 在 00:34–00:38 把 Q1/Q2/Q4/Q6–Q12/Q14 全部落地了，
但其中 **3 项是半改、1 项越了边界**。半改比不改更贵——因为状态表已经写成 ✅，
下一轮实验（W1 v6 重跑、W0 learn 压测）会拿着一个「以为修好了」的代码去归因。
所以本文对每一项固定给 8 段：**现状判定 / 目标 / 改哪一行 / 陷阱（弯路） / 单测 / lab 验证 / 回滚点 / 边界**。

---

## 0. 阅读与执行约定

1. **一条 N 一个 PR**（N1+N2 可同 PR，必须分 commit）。每个 PR 描述必须回答三问：
   动了哪张 map / ABI？fail-open 线在哪一行？哪个计数器能证明它生效？
2. 「现状判定」三态：`✅ 已达标` / `◐ 半改（有洞）` / `✗ 未做`。**只有 ✅ 才允许写进状态表。**
3. 所有行号基于 rc47-qfix（`stat` 时间 08-04 00:34–00:38）。改动后行号会漂，
   以**函数名 + 引用的代码片段**为准，不要只按行号跳。
4. 本文所有「验证命令」都可直接复制。lab 相关的一律落在 112 的 `/root/singbox/`，
   **不要经 `/tmp`**（tmpfs 仅 ~484M）。

---

## 1. rc47-qfix 复核总表

| # | 项 | 现状判定 | 说明 | 后继工单 |
|---|---|---|---|---|
| Q1 | 协调器指针竞态 | ✅ 已达标 | `closeOutboundOffload` 不再置 nil；`closed` 标志 + `isClosed()`；`Verdict()/Splice()` 在 closed 时返回 nil | — |
| Q2 | InterfaceUpdated 无条件 InvalidateAll | **◐ 半改** | 指纹门控在了，但**指纹先提交后失败不重试**、**rule-set 内容变化漏检**、**refreshErr 时完全跳过** | **N1 / N2** |
| Q3 | sniff 门过严 → learn 永不触发 | ✗ 未做 | `verdictUsedSniff` 未动（与文档一致） | **§3 完整方案** |
| Q4 | learn 取址 | ✅ 已达标（1 nit） | 优先 `metadata.Destination` → `DestinationAddresses[0]` → peer；`Unmap()` 比较；不一致则拒写 | N5（可选） |
| Q5 | per-pair goroutine/epoll | ✗ 未做 | 每 pair 仍 3 goroutine + 1 epoll fd + 2s TCP_INFO | **§4 完整方案** |
| Q6 | 先 map 后门控 | ✅ 已达标（1 nit） | 6 个门全部前移到 `BeginPair` 之前；拒绝路径 0 次 map 写 | N9（可选） |
| Q7 | 堆分配 / 三份 unwrap | **◐ 半改** | 惰性 buffer ✅、深度上限 ✅、合并成 2 份 ✅；但 `walkConnChain` **永远返回 true**，深度超限不 refuse，注释与实现相反 | **N4** |
| Q8 | Close 语义 | ✅ 已达标 | `InvalidateAll` 失败 Warn + 回落 `SetEnabled(false)`；`VerdictBackend.Close` 先写 `enabled=0` 再丢 fd（不关 fd，inbound 所有） | — |
| Q9 | Export O(n) 移位 | ✅ 已达标（可简化） | 满 256 后升级成环形，`Export()` 顺序正确（已手工推演 head/count 三态） | N6b（可选简化） |
| Q10 | 统计下标硬编码 | ✅ 已达标 | `spliceStat*` 常量 + `spliceStatCount==6` 断言；lookup 失败返回零值 + err；stats map 是普通 ARRAY（非 PERCPU），单 u64 读取无 ABI 风险 | — |
| Q11 | 容量上限 | **◐ 越界** | 上限 clamp 在了但**无 Warn**；`max_pairs<16` 被改成**启动 error**——直接违反合同 §4「不得让已上线字段开始报错」 | **N3** |
| Q12 | 可观测 | ✅ 已达标 | splice 首样本 Info、失败增量 Warn；verdict 首样本必打 | N8（可选） |
| Q13 | 卫生 | ✅ | `gofmt -l common/ebpf protocol/ebpf` 空 | — |
| Q14 | drain 错误吞掉 | ✅ 已达标 | `nr>0` + 真错误 → `return E.Cause(rerr, "drain recvq read after partial")` | — |
| — | 单测 | **◐ 缺口** | Q2/Q7/Q9/Q11/Q14 五项改动**零单测**；只有 Q4 补了 3 个 case | **N10** |

**结论**：可以进入 W1 v6 重跑分诊之前，**必须先做 N1+N2**（否则 `gen_mismatch` 这一路的分诊结论不可信）；
N3 是合同违约，必须回退；N4 是「注释说了但没做」，会误导下一个读代码的人。

---

## 2. 新发现逐项整改（N1–N10）

### N1（P0）Q2 半改：指纹在 InvalidateAll 成功之前就提交了

**现状判定** ◐。`protocol/ebpf/outbound.go:254` `InvalidateVerdictIfNeeded`：

```go
	c.lastBypassFingerprint = fingerprint   // ← 先提交
	c.lastInvalidate = time.Now()
	c.access.Unlock()

	v := c.Verdict()
	if v == nil {
		return false
	}
	if err := v.InvalidateAll(); err != nil {   // ← 后失败
		c.warn("eBPF verdict InvalidateAll reason=", reason, " failed: ", err)
		_ = v.SetEnabled(false)
		return false
	}
```

**为什么是问题**：`InvalidateAll()` 写 control map 失败（EBADF / ENOENT / 权限），此时
①指纹已经等于新值，下一次 `InterfaceUpdated` 比较相等 → **永不重试**；
②旧 generation 的条目仍然合法 → 内核继续按**已经过期的 bypass 面**放行 DIRECT；
③唯一的兜底 `SetEnabled(false)` 的错误被 `_ =` 丢掉，如果它也失败，就是**静默的永久放行**。
这正好落在 F-4「verdict hit 只能意味着不捕获，不能造成路由语义漂移」的反面。

**目标**：指纹是「已成功让内核作废」的凭证，只能在成功后提交。失败必须留痕 + 下次重试 + 兜底可见。

**改哪一行**（`outbound.go` `InvalidateVerdictIfNeeded`）：

```go
	c.access.Lock()
	prev, seeded := c.lastBypassFingerprint, c.fingerprintSeeded
	if !seeded {
		c.lastBypassFingerprint = fingerprint
		c.fingerprintSeeded = true
		c.access.Unlock()
		return false
	}
	if prev == fingerprint {
		c.access.Unlock()
		return false
	}
	c.access.Unlock()          // ← 不在这里提交指纹

	v := c.Verdict()
	if v == nil {
		return false           // 没有 backend，指纹保持旧值（下次仍会尝试）
	}
	if err := v.InvalidateAll(); err != nil {
		c.warn("eBPF verdict InvalidateAll reason=", reason, " failed (will retry on next interface update): ", err)
		if err2 := v.SetEnabled(false); err2 != nil {
			// 内核仍可能放行且我们无法关闭 —— 这是必须让人看见的最坏情况。
			c.warn("eBPF verdict SetEnabled(false) fallback ALSO failed; kernel DIRECT bypass may still be active: ", err2)
		} else {
			c.logger.Info("eBPF verdict disabled (enabled=0) after InvalidateAll failure reason=", reason)
		}
		return false           // 指纹未提交 → 下次重试
	}
	c.access.Lock()
	c.lastBypassFingerprint = fingerprint
	c.lastInvalidate = time.Now()
	c.access.Unlock()
	c.logger.Info("eBPF verdict InvalidateAll reason=", reason, " generation=", v.Generation())
	return true
```

同时在结构体（`outbound.go:39-42`）加 `fingerprintSeeded bool`，见 N7。

**陷阱（弯路）**
- 不要为了「简单」把整段包在一个 `c.access.Lock()` 里：`InvalidateAll()` 里有 syscall，
  持锁做 syscall 会把 `enabled()/Verdict()/Splice()` 这些**每连接热路径**读锁堵住。
  必须保持「短锁读 → 解锁 syscall → 短锁提交」三段式。
- `SetEnabled(false)` 之后**不要**自作聪明地加自动 re-enable 定时器。关掉就关到重启，这是安全侧。
- 不要把 `return false` 改成 `return err`：这个函数在 `InterfaceUpdated` 里被调用，
  `InterfaceUpdated` 无返回值，fail-open 语义不能变。

**单测**（新建 `protocol/ebpf/verdict_invalidate_test.go`，纯逻辑、不需要内核）
把 `v := c.Verdict()` 这一步抽成一个小接口字段（`verdictInvalidator interface{ InvalidateAll() error; SetEnabled(bool) error; Generation() uint32 }`）
以便注入 stub。断言四条：
1. 首次调用只 seed，不 invalidate，返回 false；
2. 指纹不变 → 不 invalidate；
3. 指纹变化 + stub 返回 nil → invalidate 一次、指纹提交、再次同指纹不再 invalidate；
4. 指纹变化 + stub 返回 error → 返回 false、**指纹未提交**、`SetEnabled(false)` 被调用一次；
   再次以同一新指纹调用 → **再次尝试 invalidate**（这条就是 N1 的回归测试）。

**lab 验证**（112）
```bash
grep -c "InvalidateAll reason=interface-updated" /var/log/sing-box.log
```
在 `ip -6 addr` 反复变化 10 分钟内该计数应为 0（指纹不变），而人为改一个地址后应恰好 +1。

**回滚点**：本项只动 `InvalidateVerdictIfNeeded` 一个函数，回滚 = 恢复该函数。

**边界**：不得放宽成「指纹变了也不 invalidate」；不得改 generation 语义；不得引入异步/延迟 invalidate。

---

### N2（P0）Q2 半改：指纹漏检 rule-set 内容变化；refreshErr 时完全跳过 invalidate

**现状判定** ◐。`protocol/ebpf/inbound.go:721-746`：

```go
	fp := bypassFingerprint(i.localInterfacePrefixes())
	if backend := i.backendInstance(); backend != nil {
		v4, v6 := backend.BypassCIDRCount()
		fp = fp + "|map=" + strconv.Itoa(v4) + "," + strconv.Itoa(v6)
	}
	i.bypassRuleSetAccess.Unlock()
	if i.outboundCoord != nil && refreshErr == nil {
		i.outboundCoord.InvalidateVerdictIfNeeded(fp, "interface-updated")
	}
```

两个洞：

**(a) 内容变化、计数不变 → 漏 invalidate。** 指纹里 rule-set 侧只贡献了**条数** `v4,v6`。
rule-set 更新把 `1.2.0.0/16` 换成 `3.4.0.0/16`（条数不变）时，指纹相同 → 不 invalidate →
学到的 DIRECT 条目继续生效，而 bypass 面已经变了。相对旧的「无条件 invalidate」，这是**放宽**，
直接违反合同 §4「安全门只能加不能减」。注意上面已经算出了 `updated`（rule-set 真的变了），
却只用于打日志。

**(b) `refreshErr != nil` 时一次都不 invalidate。** 刷新失败意味着 bypass 面**可能已经不对了**，
此时最安全的动作是作废缓存，而不是保留。现在是反的。

**目标**：`invalidate` 的触发条件 = 「本地前缀指纹变化」**或**「rule-set 真的 updated」**或**「刷新失败」。
只有这三者都不成立时才允许安静跳过。

**改哪一行**（`inbound.go` `InterfaceUpdated`）：

```go
	fp := bypassFingerprint(i.localInterfacePrefixes())
	if backend := i.backendInstance(); backend != nil {
		v4, v6 := backend.BypassCIDRCount()
		fp = fp + "|map=" + strconv.Itoa(v4) + "," + strconv.Itoa(v6)
	}
	i.bypassRuleSetAccess.Unlock()

	if i.outboundCoord != nil {
		switch {
		case refreshErr != nil:
			// 刷新失败 → bypass 面不可信，强制作废（安全侧，忽略指纹）。
			i.outboundCoord.InvalidateVerdictNow("bypass-refresh-failed")
		case updated:
			// rule-set 内容确实变了（条数可能不变），强制作废并把新指纹作为基线。
			i.outboundCoord.InvalidateVerdictNow("bypass-ruleset-updated")
			i.outboundCoord.NoteBypassFingerprint(fp)
		default:
			i.outboundCoord.InvalidateVerdictIfNeeded(fp, "interface-updated")
		}
	}
```

`InvalidateVerdictNow(reason string) bool` 是新增的小函数：跳过指纹比较，直接走 N1 里那段
「syscall → 失败 Warn + SetEnabled(false) → 成功记 `lastInvalidate`」逻辑。
把 N1 的成功/失败处理抽成 `func (c *outboundCoordinator) doInvalidate(reason string) bool`，
`InvalidateVerdictNow` 和 `InvalidateVerdictIfNeeded` 都调用它——**不要复制两份错误处理**。

`NoteBypassFingerprint` 目前是死代码（见 N6），这里正好是它的唯一正当用途：
强制 invalidate 之后把新指纹设成基线，避免下一 tick 再 invalidate 一次。

**陷阱（弯路）**
- **不要**把 `refreshErr != nil` 时的 invalidate 做成「顺便 `SetEnabled(false)`」。
  刷新失败通常是暂时的（网络/文件），作废一代就够；关闭要留给 `InvalidateAll` 自己失败的时候。
- `updated` 是在 `bypassRuleSetAccess` 锁内算出来的；**不要**把 `InvalidateVerdictNow` 的调用挪进锁内
  （syscall 持锁）。当前代码已经在 `Unlock()` 之后，保持这样。
- 更彻底的做法是把 rule-set 前缀内容也哈希进指纹。**本轮不要做**：
  `BypassCIDRCount()` 之外没有现成的内容读取接口，为它加一个 map dump 会引入新的
  「每次 InterfaceUpdated 全量读 map」开销。用 `updated` 布尔是零成本且更准的信号。
- 不要因为「怕 invalidate 太频繁」而给这三条路加节流。频繁 invalidate 只损失 learn 命中率，
  漏 invalidate 会损失路由正确性——两者不对称。

**单测**：在 N1 的 stub 基础上加两条——`refreshErr` 路径调用 `doInvalidate` 一次；
`updated=true` 且指纹不变时仍调用一次且随后 seed 新指纹。
（`InterfaceUpdated` 本体依赖真实 backend，测不了；把三分支决策抽成
`func decideInvalidateReason(refreshErr error, updated bool) (string, bool)` 这样的纯函数再测。）

**lab 验证**：改 rule-set 文件内容但保持条数不变，reload，日志应出现
`InvalidateAll reason=bypass-ruleset-updated`；随后 `gen_mismatch` 在下一个统计周期上升
（证明旧条目确实被作废）。

**回滚点**：`InterfaceUpdated` 的 switch 段 + 协调器新增的两个小函数。

**边界**：同 N1。另外**不得**因为这项而改动 `refreshBypassRuleSetsLocked` 的返回语义。

---

### N3（P1）Q11 越界：`max_pairs < 16` 变成了启动错误；clamp 无 Warn

**现状判定** ◐ 越界。`protocol/ebpf/outbound.go:358-375`：

```go
	// Q11: lower bound hard error; upper bound clamp+Warn (do not break existing configs).
	if options.Splice.MaxPairs > 0 && options.Splice.MaxPairs < minCapacityVal {
		return options, E.New("outbound_offload.splice.max_pairs must be 0 (default) or >= 16")
	}
	if options.Splice.MaxPairs > maxPairsCap {
		options.Splice.MaxPairs = maxPairsCap
	}
	if options.Verdict.MaxEntries > 0 && options.Verdict.MaxEntries < minCapacityVal {
		options.Verdict.MaxEntries = minCapacityVal
	}
	if options.Verdict.MaxEntries > maxEntriesCap {
		options.Verdict.MaxEntries = maxEntriesCap
	}
```

三个问题：
1. **合同违约**：`docs/ebpf-code-review-directions-20260804.md` Q11 边界原文是
   「必须 clamp+Warn，**不得变成启动错误**（已上线字段不能开始报错）」。
   `max_pairs: 8` 的配置在 rc46 能启动，在 rc47 启动失败——这是回归。
   注释自己写着 "do not break existing configs" 却做了相反的事。
2. **不一致**：同一个下限，`max_pairs` 报错、`verdict.max_entries` 静默 clamp。
3. **四处 clamp 全部静默**：用户配 `max_pairs: 1000000` 实际跑 262144，日志里一个字都没有。

**目标**：四个边界统一为 clamp + Warn；一行都不新增启动错误。

**改哪一行**：

```go
	// Q11/N3: 容量一律 clamp + Warn，绝不新增启动错误（已上线字段不得开始报错）。
	if options.Splice.MaxPairs != 0 {
		if options.Splice.MaxPairs < minCapacityVal {
			warnings = append(warnings, F.ToString("outbound_offload.splice.max_pairs=", options.Splice.MaxPairs,
				" raised to ", minCapacityVal))
			options.Splice.MaxPairs = minCapacityVal
		} else if options.Splice.MaxPairs > maxPairsCap {
			warnings = append(warnings, F.ToString("outbound_offload.splice.max_pairs=", options.Splice.MaxPairs,
				" clamped to ", maxPairsCap))
			options.Splice.MaxPairs = maxPairsCap
		}
	}
	// verdict.max_entries 同构处理
```

`normalizeOutboundOffloadOptions` 现在只返回 `(options, error)`，没有 logger。两个选择，**选 A**：
- **A（推荐）**：签名改成 `(option.EBPFOutboundOffloadOptions, []string, error)`，
  第二个返回值是 warning 文本；调用方（`normalizeListenOptions` / inbound 构造处）逐条 `logger.Warn`。
  纯函数保持可测。
- B：把 logger 传进去。会让这个纯函数变得难测，**不要选**。

**陷阱（弯路）**
- `MaxPairs == 0` 是「用默认值」的合法含义（默认 65536 在 `startSplice` 里给），
  clamp 逻辑必须显式排除 0，不要写成 `if MaxPairs < 16 { MaxPairs = 16 }`（会把 0 改成 16，等于悄悄把默认从 65536 降到 16）。**这是最容易踩的一脚。**
- `TTL < 0` / `IdleTimeout < 0` 保持现有的启动错误——它们是**新字段**，从未以负值上线过，不受该边界约束。不要顺手也改成 clamp。
- 上限常量 262144 必须同时写进 zh/en 文档；不写文档的 PR 视为未完成。

**单测**（补进 `verdict_learn_test.go`，`TestNormalizeOutboundOffloadCapacityClamp`）：
`max_pairs=8 → 16 且 warnings 非空且 err==nil`（这条就是 N3 回归测试）、
`max_pairs=0 → 0`、`max_pairs=999999 → 262144`、`max_entries` 同上四条。

**lab 验证**：用 `max_pairs: 8` 起进程，必须**能启动**，日志有一条 Warn。

**回滚点**：单函数 + 调用方签名。

**边界**：不得删除/改名任何字段；不得把 clamp 上限调低于 262144；不得把 0 的语义改掉。

---

### N4（P1）Q7 半改：`walkConnChain` 永远返回 true，深度超限不 refuse

**现状判定** ◐。`protocol/ebpf/splice_bridge.go:456-480`：

```go
// walkConnChain visits conn and Upstream/NetConn wrappers without heap maps (Q7).
// fn return true to stop early. Returns false if depth exceeded.
func walkConnChain(conn net.Conn, fn func(net.Conn) bool) bool {
	for depth := 0; depth < connChainMaxDepth && conn != nil; depth++ {
		if fn(conn) {
			return true
		}
		...
		break
	}
	return true          // ← 深度超限、走完、break 全部返回 true
}
```

调用方：

```go
	ok := walkConnChain(conn, func(c net.Conn) bool { ... })
	if !ok {
		return nil        // ← 死代码，永不进入
	}
```

**为什么是问题**：不是当下的功能 bug（`found == nil` 时 `spliceTCPFromConn` 仍然返回 nil → 拒绝 splice，
行为恰好正确），而是**契约谎报**：注释承诺「深度超限返回 false」，实现没有；
`refuseIfBuffered` / `flushCachedToRemote` 这两个调用方**完全忽略返回值**——
也就是说「链条超过 16 层，后面还有没检查的 buffer / 没 flush 的 cache」这种情况会被当作
「检查通过」，然后 Activate。这是 A-2「字节只能被内核或用户态之一搬运」的潜在破口，
只是目前没有 16 层深的 wrapper 才没炸。留着这个注释，下一个人会理所当然地相信它。

**目标**：三个调用方都能区分「走完整条链」和「链条太深，没看完」。太深 → 一律拒绝 splice。

**改哪一行**：把返回值语义改成「是否**完整**走完（未被深度截断）」，早停不算截断：

```go
// walkConnChain 遍历 conn 及其 Upstream/NetConn 包装（Q7：无 heap map）。
// fn 返回 true 表示提前结束遍历（视为完整）。
// 返回 false 仅表示 **深度超过 connChainMaxDepth 而被截断**，调用方必须据此拒绝 splice。
func walkConnChain(conn net.Conn, fn func(net.Conn) bool) bool {
	depth := 0
	for ; conn != nil; depth++ {
		if depth >= connChainMaxDepth {
			return false          // 截断：链条没看完
		}
		if fn(conn) {
			return true           // 早停：调用方已拿到答案
		}
		// ... Upstream / NetConn 下钻，next == conn 时 break
		break
	}
	return true                   // 自然走完
}
```

三个调用方：
- `spliceTCPFromConn`：保留 `if !ok { return nil }`（现在它不再是死代码）。
- `refuseIfBuffered`：`if !walkConnChain(...) && refuseErr == nil { refuseErr = E.New("conn wrapper chain too deep; skip splice") }`。
- `flushCachedToRemote`：同理，截断 → 返回 error（调用方 `coord.info` + fail-open）。

`common/ebpf/splice.go:562` 的 `unwrapTCPConn` 有同样的 16 层上限但返回 `(conn, bool)`，
语义已经对了，**不要动它**，也不要试图把两份合并——`common/ebpf` 不得反向依赖 `protocol/ebpf`（合同 §4）。
两份并存是有意的，在两处各留一行注释指向对方即可。

**陷阱（弯路）**
- 不要把 `connChainMaxDepth` 调大来「绕过」这个问题。16 层已经远超实际（真实链条 ≤4 层）。
- 不要把截断做成 Warn 后继续 splice。fail-open = 退回用户态拷贝，不是「继续冒险」。
- 改完必须确认 `spliceTCPFromConn` 的早停语义没被搞反：找到 TCPConn 时 `fn` 返回 true，
  必须仍然是「成功」而不是「截断」。这就是把 `depth >= max` 的检查放在 `fn` **之前**的原因。

**单测**（新建 `protocol/ebpf/conn_chain_test.go`）：构造一个 `type nestConn struct{ net.Conn; up net.Conn }`
实现 `Upstream() any`，套 20 层，断言：
1. `walkConnChain` 返回 false；
2. `spliceTCPFromConn` 返回 nil（即便最内层真的是 `*net.TCPConn`）；
3. 4 层时返回 true 且能取到最内层 TCPConn；
4. 自引用（`up == self`）不死循环。

**lab 验证**：不需要（纯用户态逻辑，单测足够）。

**回滚点**：单函数 + 三个调用点。

**边界**：不得让 `common/ebpf` 依赖 `protocol/ebpf`；深度超限只能 refuse，不得 Warn-and-continue。

---

### N5（P2）Q4 nit：skip 原因失真 + eBPF inbound 下 peer 兜底不可达

**现状判定** ✅ 主体达标，两个 nit。`protocol/ebpf/verdict_learn.go:198-204`：

```go
	dest := resolveLearnDestination(metadata, remote)
	if !dest.IsValid() {
		backend.Skip()
		c.debug("eBPF verdict learn skip: reason=", verdictSkipAddrMismatch, " (empty/mismatch dest)")
		return
	}
```

1. `resolveLearnDestination` 用同一个「invalid」表达两种情况：**没有可用地址**（应为 `verdictSkipNoDest`）
   和**preferred≠peer 不一致**（`verdictSkipAddrMismatch`）。日志一律报 addr-mismatch。
   W1/W0 分诊时会把「metadata 没地址」误读成「DNS 改写导致不一致」——**正是本文要消除的弯路**。
   `verdictSkipNoDest` 现在从 `MaybeLearnTCP` 已不可达。
2. 兜底 `if peerOK { return remoteAddr }`：模块 A 只在 `metadata.InboundType == C.TypeEBPF` 下学习，
   而 eBPF inbound 的 `metadata.Destination` 来自 `backend.TakeOriginal()`，**必然是 IP 形式**
   （`inbound.go:782` `M.SocksaddrFromNetIP(original.Destination)`）。所以 peer 兜底实际不可达；
   万一可达（未来接入其它 inbound），写 peer key 而内核查的是 app dial 的地址，
   **这条目 100% 查不中**，只会白占 LRU 并挤掉有用条目。

**改哪一行**：让函数返回原因，兜底显式拒绝：

```go
func resolveLearnDestination(metadata adapter.InboundContext, remoteAddr netip.AddrPort) (netip.AddrPort, int) {
	// ...
	if preferred.IsValid() && preferred.Addr().IsValid() && preferred.Port() != 0 {
		if peerOK {
			pa, ra := preferred.Addr().Unmap(), remoteAddr.Addr().Unmap()
			if pa != ra || preferred.Port() != remoteAddr.Port() {
				return netip.AddrPort{}, verdictSkipAddrMismatch
			}
		}
		return preferred, verdictSkipNone
	}
	// 没有 metadata 侧地址：peer key 与内核 connect4/6 的查表 key 不同源，
	// 写进去必然查不中，只会白占 LRU —— 显式拒绝，不再兜底。
	return netip.AddrPort{}, verdictSkipNoDest
}
```

调用方按返回的 reason 打日志与计数。

**陷阱**：不要顺手改 `VerdictStats` 的字段（合同 §4：`Export()`/`VerdictEntry` 是导出 API）。
skip reason 只进日志，不进 stats 结构。

**单测**：把现有 3 个 `TestResolveLearnDestination_*` 改成断言 `(addr, reason)` 二元组，
新增 `TestResolveLearnDestination_NoMetadataDestReturnsNoDest`。

**边界**：不得放宽成「不一致时写两个 key」；不得移动 `route/conn.go` 的 hook 位置。

---

### N6（P2）死代码与谎报注释三处

| 位置 | 现象 | 改法 |
|---|---|---|
| `outbound.go:39-40` | `// Q2: throttle no-op InterfaceUpdated invalidate storms` + `lastInvalidate` 字段**只写不读**，节流根本没实现 | 指纹门控已经把风暴问题解决了，节流没必要。**删掉误导性注释**，`lastInvalidate` 保留为「最近一次成功作废时间」并在 verdict 统计日志里打出来（对 W1 分诊有用），或者一起删掉。二选一，不要留半句话 |
| `outbound.go:288` `NoteBypassFingerprint` | 定义了从未被调用 | N2 里成为唯一正当调用点；若不做 N2 则删除 |
| `verdict.go:143-161` `recordExport` | `exportLog` + `exportRing` 双表示，`exportCount` 只在一种状态下有意义（已推演正确，但读者需要 5 分钟才能确信） | 可选简化：一开始就 `make([]VerdictEntry, verdictExportCap)` + `head/count` 两个 int，`Export()` 单一路径。**行为必须逐字节等价**，且要有 N10 的环绕单测护着才允许改 |

---

### N7（P2）指纹用空串当哨兵

`outbound.go:259` 用 `prev == ""` 判断「没 seed 过」。当前安全，因为 `bypassFingerprint`
在无前缀时返回 `"empty"`，再拼 `"|map=0,0"`，永远非空。但这是**靠远处一个实现细节兜着的**：
哪天指纹构造改成只拼 map 计数、或某条路径传了 `""`，就会退化成「每 tick 都 seed，永不 invalidate」——
一个静默的安全放宽。N1 的补丁里已经改成显式 `fingerprintSeeded bool`，这里只是把理由记下来：
**别把「无效值」和「未初始化」用同一个值表达。**

---

### N8（P2）splice 统计错误被吞

`runtime_stats.go:162-175` `spliceRuntimeStats`：`backend.RuntimeStats()` 出错 → `return ..., false`
→ 整个 splice 统计行**不打印**，且没有任何 Warn。于是「统计消失」和「splice 未启用」在日志里长得一样。
Q10 刚把 `RuntimeStats` 改成「失败返回零值 + err」，这里正好把 err 丢了。

改法：出错时打一条 Warn（带节流：连续失败只在第一次和状态变化时打），再返回 false：

```go
	stats, err := backend.RuntimeStats()
	if err != nil {
		if !i.spliceStatsErrLogged {
			i.logger.Warn("eBPF outbound splice metrics unavailable: ", err)
			i.spliceStatsErrLogged = true
		}
		return ECommon.SpliceStats{}, false
	}
	i.spliceStatsErrLogged = false
```

**边界**：不得因此新增配置项或缩短 `runtimeStatsInterval`（合同 §4）。

---

### N9（P2）`flushCachedToRemote` 写的是解包后的 TCPConn

`splice_bridge.go:81` 传的是 `remoteTCP`（`*net.TCPConn`）而非 `remote`（最外层 `net.Conn`）。
若 remote 侧存在任何会变换字节的 wrapper，缓存数据会绕过它直接落到裸 fd。
目前靠 E4（`allow_outbound_types` 默认只 `direct`）挡着，所以不是现实缺陷。
**加固建议**（可选，属于 §4「安全门只能加不能减」的正向增量）：要求 remote 在 depth 0 就是
`*net.TCPConn` 或 `adapter.SpliceCapableConn`，否则拒绝 splice；这样「链条里有 TCPConn」
和「本身就是 TCPConn」不再混淆。做的话必须先在 lab 确认 direct 出站的 remote 确实是 depth 0
（否则会把正常路径全拒掉——先加一条 Info 日志观察一轮再决定）。

---

### N10（P1）单测缺口：五项 Q 改动零测试

「整改少走弯路」最直接的手段就是每个 Q 落地时钉一条回归测试。当前缺口：

| 缺口 | 测试文件 | 测试名 | 关键断言 |
|---|---|---|---|
| Q2 指纹门控 | `protocol/ebpf/verdict_invalidate_test.go`（新） | `TestInvalidateVerdictIfNeeded_*` | 见 N1 四条 + N2 两条 |
| Q7 深度上限 | `protocol/ebpf/conn_chain_test.go`（新） | `TestWalkConnChainDepth*` | 见 N4 四条 |
| Q9 环形缓冲 | `common/ebpf/verdict_export_test.go`（新） | `TestVerdictExportRingWrap` | 写 300 条后 `Export()` 长度 == 256、**最旧在 [0]、最新在 [255]**、内容与写入序列的后 256 条逐字段相等 |
| Q11 clamp | `protocol/ebpf/verdict_learn_test.go` | `TestNormalizeOutboundOffloadCapacityClamp` | 见 N3 |
| Q14 drain 错误 | `protocol/ebpf/drain_test.go`（新） | `TestDrainTCPRecvToPartialThenError` | 用 `net.Pipe` 不够（需要 FIONREAD）→ 用真实 `net.TCPConn` 对（`net.Listen("tcp","127.0.0.1:0")`），写入后关闭 dst 使 `dst.Write` 失败，断言返回 error 而非 nil |

Q9 的环绕测试**必须先写、再做 N6 的简化**，否则重写环形缓冲时无从判断等价。

`common/ebpf/verdict.go` 是 `cgo` build tag，`Export()`/`recordExport` 不碰 map，
构造 `&VerdictBackend{}` 直接调 `recordExport` 即可测（`verdictMap` 保持 0 值也不会被触及）。

---

## 3. Q3 完整落地方案：learn 的依据必须来自路由决策，而不是 metadata 推断

这是模块 A 的生死线。当前 `verdictUsedSniff`（`verdict_learn.go:86-99`）用
`metadata.Protocol != "" || metadata.Client != "" || metadata.SniffHost != ""` 推断
「路由用了 sniff 结果」。但这三个字段是 **sniff 自己填的**，与路由是否用过它们无关：
开了 sniff 的生产配置里，`Protocol` 几乎恒非空 → learn 永远 skip → 模块 A 价值为 0；
而反向的 `allow_with_sniff=true` 会静默绕过域名路由（F-4 危险），不是答案。

### 3.1 设计：`RouteMatchInputs` 位掩码（累计「被求值过的条件类」）

**关键洞察（最容易走的弯路）**：不能只记录**命中规则**用了哪些条件，
必须累计**所有被求值过**的条件类——**包括未命中的规则**。
理由：如果第 3 条规则是 `domain_suffix: youtube.com → proxy`，目标因为域名不匹配才落到 direct，
那么这次 direct 决策**依赖域名**。把它学成 DIRECT，下一个解析到同一 IP 的 `youtube.com` 请求
就会被内核直连绕过——路由语义漂移，正是 F-4 禁止的。

在 `adapter.InboundContext` 上加一个字段（与已有的 `DidMatch bool` 同一性质，有先例）：

```go
// adapter/inbound.go
type RouteMatchInputs uint32

const (
	RouteMatchIP RouteMatchInputs = 1 << iota  // ip_cidr / geoip / ip_is_private / ip_version
	RouteMatchPort                             // port / port_range
	RouteMatchNetwork                          // network / network_type / inbound / inbound_interface
	RouteMatchDomain                           // domain* / geosite / rule_set(domain) / adguard
	RouteMatchProtocol                         // sniffed protocol
	RouteMatchClient                           // sniffed client
	RouteMatchProcess                          // process_name/path/package_name
	RouteMatchUser                             // auth_user / user_id
	RouteMatchOther                            // clash_mode / preferred_by / query_type / ...
	RouteMatchUnknown                          // 无法归类 → fail closed
)

// verdict-learn 白名单：只有这些类参与过决策时，destination-level DIRECT 缓存才等价。
const RouteMatchIPOnly = RouteMatchIP | RouteMatchPort | RouteMatchNetwork
```

**实现位置**（改动面比逐个 item 改小得多）：给 `route/rule.RuleItem` 加一个**可选**接口

```go
// route/rule/rule_default.go
type RuleItemClass interface {
	MatchClass() adapter.RouteMatchInputs
}
```

在 `abstractDefaultRule.matchInner` / `evaluateForMerge` / `evaluateGroups` 里，
**调用 `item.Match()` 之前**就 OR 进去（求值过就算，不管结果）：

```go
	for _, item := range r.items {
		metadata.DidMatch = true
		metadata.MatchInputs |= itemMatchClass(item)   // ← 求值前 OR
		if !item.Match(metadata) {
			return false
		}
	}

func itemMatchClass(item RuleItem) adapter.RouteMatchInputs {
	if c, ok := item.(RuleItemClass); ok {
		return c.MatchClass()
	}
	return adapter.RouteMatchUnknown   // ← fail closed：没实现的一律算未知
}
```

然后每个 `rule_item_*.go` 加一个三行方法。**没加的自动 fail-closed**，
所以可以增量推进：先给 IP/port/network 那几个加上，其余全落进 `RouteMatchUnknown`，
learn 于是天然保守；随着逐个补齐而逐步放开。这是这套设计最大的好处——**不存在「漏一个就放宽」的风险**。

`RuleSetItem` 特殊：rule-set 内可能同时含 IP 和 domain 规则 →
只要 rule-set 里存在 domain 类内容，就 OR `RouteMatchDomain`（编译期即可知）；无法确定则 `RouteMatchUnknown`。

### 3.2 门控改法（`verdict_learn.go`）

```go
func verdictRouteInputsOK(metadata adapter.InboundContext, allowWithSniff bool) bool {
	if metadata.MatchInputs == 0 {
		// 一条规则都没求值过（默认出站直连）→ 决策与域名无关，可学。
		// 注意：必须确认路由确实走完了规则链，而不是「字段没被填」。见 3.4 陷阱。
		return true
	}
	if metadata.MatchInputs&adapter.RouteMatchUnknown != 0 {
		return false
	}
	if metadata.MatchInputs&^adapter.RouteMatchIPOnly != 0 {
		return allowWithSniff && false   // 见下：allow_with_sniff 不再能放开域名类
	}
	return true
}
```

`allow_with_sniff` 的处置（合同 §4：已上线字段只能 deprecate 不能删）：
保留字段与解析，但**运行时不再放开 `RouteMatchDomain|Protocol|Client|Process|User`**；
置 true 时打一条 Warn：`allow_with_sniff is deprecated and no longer relaxes domain-based routing (see Q3)`。
旧的 `verdictUsedSniff` 保留为**第二道门**（与新门 AND，不是 OR）——安全门只能加不能减。

### 3.3 分阶段交付

| 阶段 | 内容 | 门禁 |
|---|---|---|
| P1 | `RouteMatchInputs` 类型 + `InboundContext` 字段 + `matchInner` 累计 + `itemMatchClass` fail-closed（**所有 item 都不实现 MatchClass**） | 全绿单测；learn 行为与现在等价或更严（`MatchInputs` 恒含 Unknown → 全 skip）。**这一步可以独立合并，零行为风险** |
| P2 | 给 IP/port/network 类 item 实现 `MatchClass()`；新门与旧 `verdictUsedSniff` AND | 负向单测（见 3.5）；无 sniff 配置下 learn 首次真正产生写入 |
| P3 | 给 domain/protocol/client/process/user 类 item 实现 `MatchClass()`（此时它们从 Unknown 变成具名类，语义不变但日志可读） | 在开 sniff 的配置下跑 W0 200 连接实验，四条判据 |
| P4 | `allow_with_sniff` deprecate Warn + 文档 | zh/en 文档同步 |

**P1 不需要 route 侧评审即可合并**（纯累加、无行为变化）；P2 起需要 route 侧独立评审——
这也是把它拆成四步的目的：把「需要评审的部分」缩到最小。

### 3.4 陷阱（弯路）

- **`MatchInputs == 0` 有二义性**：既可能是「真的没求值任何规则」，也可能是
  「路由走了某条不经过 `matchInner` 的路径」（DNS 规则、headless rule、action 直接命中等）。
  必须在 `RouteConnectionEx` 的入口把 `MatchInputs` 显式置为 `RouteMatchUnknown`，
  在规则链正常走完后再由 `matchInner` 的累加决定——**即默认 Unknown，而不是默认 0**。
  否则任何绕过 `matchInner` 的新代码路径都会静默地变成「可学」。
- **不要在 `route/**` 里引用 `protocol/ebpf`**。`RouteMatchInputs` 定义在 `adapter`，
  route 只负责填，ebpf 只负责读。
- **不要把 `MatchInputs` 做成指针或 map**：它在每连接路由热路径上被 OR，必须是值类型 uint32。
- **不要顺手改 `DidMatch` 的语义**去复用。它有自己的用途（`IgnoreDestinationIPCIDRMatch`），
  两者语义不同，混用会破坏现有 invert 逻辑。
- **`invert: true` 的规则**：条件被求值了就要计入，与 invert 无关。不要因为 `!matched` 就跳过累加——
  累加发生在 `item.Match()` 之前，天然正确，别「优化」成命中后才累加。

### 3.5 必须有的负向测试

1. `TestVerdictLearnRefusesDomainRoutedDestination`：构造 `MatchInputs = RouteMatchIP|RouteMatchDomain`
   → `evaluateVerdictLearn` 必须返回 `false, verdictSkipSniff`（或新的 `verdictSkipRouteInputs`）。
2. `TestVerdictLearnRefusesUnknownInputs`：`MatchInputs = RouteMatchUnknown` → 拒绝。
3. `TestVerdictLearnAllowsIPOnly`：`MatchInputs = RouteMatchIP|RouteMatchPort` + 空 DirectDialer → 允许。
4. `TestAllowWithSniffDoesNotRelaxDomain`：`allow_with_sniff=true` + 含 Domain → **仍然拒绝**。
5. route 侧：`TestMatchInputsAccumulatesOnRejectedRule`——第一条 domain 规则不命中、第二条 IP 规则命中，
   最终 `MatchInputs` 必须同时含 Domain 与 IP。**这条是整个 Q3 正确性的核心断言。**

### 3.6 边界

- 默认只能更严：任何一步都不允许出现「以前 skip、现在 write」而没有对应的负向测试。
- `verdict.mode` 保持 `off` 直到 P3 的 W0 四判据通过。
- 不新增配置字段（`RouteMatchInputs` 是内部字段，不进 JSON）。
- 不得删除 `allow_with_sniff`，只能 deprecate。

---

## 4. Q5 完整落地方案：backend 级单 epoll + 单清扫器

### 4.1 现状成本（rc47-qfix 实测代码路径）

每个 spliced pair：
- `watchSplicePair` goroutine 1 个（`splice_bridge.go:149`）
- `startSpliceEpollWatch` 内的 `EpollWait` goroutine 1 个（`:286`）
- 转发 `epollDone → pair.Release()` 的 goroutine 1 个（`:186`）
- epoll fd 1 个
- `liveTick` 每 **2 秒**对两端各做 1 次 `SO_ERROR` + 1 次 `TCP_INFO`（`:206,219` → `tcpConnAlive`）

`max_pairs` 默认 65536 → 满载约 **19.6 万 goroutine、6.5 万 epoll fd、每 2 秒 26 万次 getsockopt**。
控制面会吃掉数据面省下来的 CPU，且 fd 上限（`ulimit -n`）会先炸。

### 4.2 目标结构

```go
// common/ebpf/splice_watch.go（新文件，与 SpliceBackend 同包同生命周期）
type spliceWatcher struct {
	epfd    int
	access  sync.Mutex
	entries map[int32]*watchEntry   // fd -> entry（左右各一条，指向同一 pair）
	closing chan struct{}
	wg      sync.WaitGroup
}

type watchEntry struct {
	pair     *SplicePair
	otherFD  int32
	lastUp   uint64
	lastDown uint64
	stale    int
}
```

- **1 个** `EpollWait(epfd, events[128], 500ms)` goroutine（整个 backend）；
  事件 → 查 `entries[ev.Fd]` → `pair.Release()`。
- **1 个** 清扫 goroutine：每 `idle/2`（下限 5s）遍历 pair 快照做 `Bytes()` 字节静默判定，
  连续 2 轮不变 → Release。**per-pair 的 `lastUp/lastDown/stale` 移进 `watchEntry`。**
- **`liveTick`（2s TCP_INFO）整体删除**：`EPOLLERR|EPOLLHUP|EPOLLRDHUP` 已覆盖对端消失与 socket 错误，
  这正是 epoll 存在的意义。若确实需要兜底，改成清扫 goroutine 里**只对「本轮字节无变化」的 pair**
  做一次 `TCP_INFO`，频率随 `idle/2`（默认 5 分钟级），成本从 O(pairs/2s) 降到 O(静默 pairs/5min)。
- 注册/注销：`SplicePair.Activate()` 成功后 `watcher.add(pair)`；`SetOnRelease` 里 `watcher.remove(pair)`。
- **降级**：`EpollCreate1` 失败 → `watcher == nil` → `watchSplicePair` 走现有 per-pair 路径，
  并打**一条** Warn（不是每 pair 一条）。合同 §4：epoll 失败必须 Warn，不得静默降级。

### 4.3 迁移步骤（每步可独立验证）

1. **只删 `liveTick`**，其余不动 → 立刻拿到 `getsockopt` 归零的数据。风险最小，先做。
2. 引入 `spliceWatcher`，只接管 **epoll**（清扫仍在 per-pair goroutine）→ goroutine 从 3 降到 1，fd 从 N 降到 1。
3. 清扫也上移到 backend 级 → per-pair goroutine 归零。
4. 每步都要有 before/after 数字，无数字的性能 PR 直接拒（合同 §4）。

### 4.4 陷阱（弯路）

- **fd 复用是头号杀手**：`entries` 以 fd 为 key，而 fd 在 `Release()` 关闭后会被内核复用给
  下一个连接。必须保证 **`EPOLL_CTL_DEL` 与 `delete(entries, fd)` 在同一把锁内、且都发生在
  socket 被关闭之前**。做法：`remove(pair)` 由 `SetOnRelease` 在关闭 fd **之前**调用；
  并在事件处理里二次校验 `entry.pair` 仍是活的（`pair.IsReleased()`），不一致就丢弃事件。
  否则会出现「A 的事件让 B 被 Release」——极难复现，会被误判成内核 bug。
- **不得在持 `b.access` 时 `EpollWait` 或做 syscall 清扫**：先在锁内拷贝一份 pair 快照（切片），
  解锁后再逐个 `Bytes()`。当前 `RuntimeStats()` 已经是 RLock 短临界区，保持这个风格。
- **`EpollWait` 的 500ms 超时不要改成 -1**：`closing` 需要被观察到；`-1` 会让 Close 挂住。
  现有代码已经这样做了（`:291`），照抄。
- **不要顺手改两阶段配对协议**：`BeginPair → 门控 → Activate → 事后 FIONREAD 复查` 一个字都不能动，
  A-2「字节只能被内核或用户态之一搬运」是本模块的正确性根基。Q5 只碰**监视**，不碰**建立**。
- **不要降低 `max_pairs` 默认值**来「缓解」资源问题（合同 §4 明令禁止）。
- `accounting` 被 `startSplice` 强制为 true（`outbound.go:156`），清扫器可以无条件依赖 `Bytes()`；
  但仍要保留 `if !accounting { continue }` 分支，因为 `PrepareSplice` 是可被测试直接调用的公开路径。

### 4.5 验证（112）

```bash
# 造 1000 条并发长连接（PVE 侧 iperf3 -P 或 ab），然后：
ps -o nlwp= -p "$(pgrep -x sing-box)"                 # 线程数
ls /proc/"$(pgrep -x sing-box)"/fd | wc -l            # fd 数
top -b -n 3 -p "$(pgrep -x sing-box)" | tail -5       # CPU%
```
判据：step 1 后 CPU 明显下降；step 3 后线程数与 pair 数**不再线性相关**；
`iperf3 -c` v4 吞吐 ≥ 15.5 Gbits/s 且 CPU ≤14%（合同 §4 不回归线）；
`redirect_failures` / `peer_misses` 保持 0。

---

## 5. 验证矩阵（每个 PR 至少跑对应行）

| 项 | 本地（macOS/PVE） | 112 lab |
|---|---|---|
| N1/N2 | `go test -tags with_ebpf ./protocol/ebpf`（PVE，Linux） | 反复 `ip -6 addr` 变更 10 分钟 → `InvalidateAll` 计数 0；改 rule-set 内容（条数不变）→ 恰好 +1 |
| N3 | `go test` + `max_pairs: 8` 能启动 | 启动日志有 clamp Warn |
| N4 | `go test`（纯用户态） | 无需 |
| N5 | `go test` | learn skip 日志中 `reason=` 与真实原因一致 |
| N8 | — | 手动 close stats fd 难以模拟，代码审查即可 |
| N10 | `go test -tags with_ebpf ./common/ebpf ./protocol/ebpf` 全绿 | — |
| Q3 P2/P3 | 上述 5 条负向测试 | W0 200 连接四判据 + 域名路由目标**未**出现在 `Export()` |
| Q5 各步 | `go test` | §4.5 三条命令的 before/after |
| 通用 | `gofmt -l common/ebpf protocol/ebpf` 空 | `iperf3` v4 ≥15.5 Gbits/s @ ≤14% CPU；112 E2E 全绿 |

`CGO_ENABLED=0 GOOS=linux go build ./...` 目前在 `experimental/boxdd` 上失败
（`invalid reference to runtime/pprof.parseProcSelfMaps`），**与 eBPF 无关**，
不要试图在本轮「顺手修掉」，也不要把它当成本轮改动引入的回归。

---

## 6. 边界（继承 §4 + 本轮新增）

继承 `docs/framework-requirements-boundaries-20260804.md` §4 与
`docs/ebpf-code-review-directions-20260804.md` §4 全部条目，**外加**：

1. **半改即未改**：Q/N 项只有在「代码 + 单测 + 文档」三件齐备时才能在状态表标 ✅。
   状态表里出现一个没有回归测试的 ✅，视为文档缺陷。
2. **注释不得超前于实现**：像 `walkConnChain` 那种「注释承诺 false、实现永远 true」的情况，
   等同于功能缺陷处理（N4）。
3. **不得为容量/参数新增启动错误**（N3 的教训）。已上线字段的非法值一律 clamp + Warn。
4. **安全侧不对称原则**：作废过频只损失性能，作废漏掉会损失正确性；
   任何「减少 invalidate 次数」的改动都必须证明不漏（N2 的教训）。
5. **未初始化 ≠ 无效值**：不得用空串/0 同时表达两种状态（N7 的教训）。
6. Q3 的 `MatchInputs` 默认值必须是 `RouteMatchUnknown`（fail-closed），不是 0。
7. Q5 只允许改「监视」，不允许碰「配对建立」的任何一行。

---

## 7. 建议顺序与并行度

```
第 1 批（阻塞 W1 v6 重跑）：N1 → N2            ← 必须先做，否则 gen_mismatch 分诊不可信
第 2 批（合同违约与谎报，独立）：N3、N4         ← 可与第 1 批并行
第 3 批（补测试，护住已落地的 Q）：N10          ← Q9 环绕测试必须先于 N6 的简化
第 4 批（分诊质量）：N5、N6、N7、N8            ← W0 learn 压测之前做完 N5
第 5 批（模块 A 生死线）：Q3 P1 → P2 → P3 → P4  ← P1 零风险可先合；P2 起需 route 侧评审
第 6 批（可扩展性）：Q5 step1 → 2 → 3 → 4      ← 每步带数字
可选：N9（需先加 Info 观察一轮）
```

**状态表更新纪律**：`docs/ebpf-implementation-status-20260803.md` 里 Q2/Q7/Q11 目前记的是
「✅ 本轮」，与本文复核结论（◐）不符。修完 N1–N4 之前，请把这三项改成 ◐ 并指向本文——
**先让文档说真话，再谈把它变成真的。**
