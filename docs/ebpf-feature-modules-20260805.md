# eBPF 功能模块化（可换基线 / 快速合并）— 2026-08-05

目标：**功能按模块堆叠**，不要绑死在某一个 `beta4-adaptive` 长分支上。  
换 reF1nd / SagerNet 基线时：先落 **M-base**，再按需 cherry-pick **M-*** 功能模块。

关联边界：`docs/framework-requirements-boundaries-20260804.md` **边界 G**（PVE 编译）。

---

## 0. 上游版本事实（检测日 2026-08-05）

| 来源 | 最新 1.14 beta | 说明 |
|------|----------------|------|
| **reF1nd** (`origin`) | **`v1.14.0-beta.5-reF1nd`**（2026-08-04） | **没有** `beta.6` / `beta.7-reF1nd` / `beta.8-reF1nd` |
| **SagerNet** (`upstream`) | **`v1.14.0-beta.7`**（2026-08-05） | 有 beta.7；**没有** beta.8；**无** reF1nd 后缀 tag |
| 我们当前作业树 | adaptive **beta.4-reF1nd** 移植线 + eBPF 深改 | 与 stock beta.5-reF1nd 的 eBPF API **已分叉**（option 字段、outbound_offload 等） |

结论：

- 问「reF1nd 有没有 beta7/8」→ **没有**；reF1nd 停在 **beta.5**。
- 官方上游有 **beta.7**，合进我们栈要等 reF1nd 跟版，或自己 port `beta.5 → beta.7` 的 ~220 commits（成本高，单独立项）。
- 模块 cherry-pick 的**推荐基线**暂时仍是：**本树 eBPF 栈（M-base）**，而不是裸 `v1.14.0-beta.5-reF1nd`（对方 eBPF surface 更旧/不同）。

---

## 1. 模块表（依赖只向下）

```
M-base          eBPF inbound + shared_network + bypass + promote + offload 骨架
  ├─ M-dns-kernel-direct   :53 服务器 CIDR 内核直通（hijack 例外）
  ├─ M-dns-prefill         弱 DIRECT A/AAAA → TC /32 promote
  └─ M-docs-boundary-g     构建主机 PVE only 文档（可单独合）
```

| ID | 名称 | 默认 | 依赖 | 可单独关掉？ |
|----|------|------|------|----------------|
| **M-base** | adaptive eBPF 栈 | 随 with_ebpf | 无（本产品基座） | 否（功能模块挂在上面） |
| **M-dns-kernel-direct** | DNS 路径拆分 | **off** | M-base（dns_direct LPM + TC/cgroup） | 是（配置 / 不 cherry-pick） |
| **M-dns-prefill** | 弱 DNS prefill | **off** | M-base promote + `DNSAnswerObserver` | 是 |
| **M-docs-boundary-g** | 边界 G 文档 | n/a | 无代码依赖 | 是 |

**禁止**：把 M-dns-* 写进「必须和 smart/adaptive 同一 commit」；禁止两个 DNS 模块互相 import 业务逻辑。

---

## 2. 文件归属（合并时按表拆 commit）

### M-dns-kernel-direct

| 路径 | 角色 |
|------|------|
| `option/ebpf.go` | `EBPFDNSKernelDirectOptions` + inbound 字段 |
| `protocol/ebpf/dns_kernel_direct.go` | normalize + `applyDNSKernelDirect` |
| `protocol/ebpf/dns_kernel_direct_test.go` | 单测 |
| `protocol/ebpf/inbound.go` | **仅** 字段 + 调用 2～3 行钩子（禁止堆逻辑） |
| `common/ebpf/backend.go` | `UpdateDNSDirectCIDR` / map FDs |
| `common/ebpf/backend_nocgo.go` | stub |
| `common/ebpf/shared_network.go` | 把 dns_direct fd 传给 TC prepare |
| `common/ebpf/native/singbox_ebpf.h` | map fd 字段 |
| `common/ebpf/native/shared_network.bpf.c` | `:53` + dns_direct LPM |
| `common/ebpf/native/shared_network_loader.c` | map 表 |
| `common/ebpf/native/shared_network_runtime.c` | fallback map |
| `common/ebpf/native/connect_prog.c` | cgroup :53 例外 |
| `include/ebpf_test.go` | JSON 片段（可与 prefill 同测文件，commit 消息拆开） |

### M-dns-prefill

| 路径 | 角色 |
|------|------|
| `option/ebpf.go` | `EBPFDNSPrefillOptions` + `outbound_offload.dns_prefill` |
| `protocol/ebpf/dns_prefill.go` | 路由干跑 + promote |
| `protocol/ebpf/inbound.go` | 注册 `DNSAnswerObserver` + 字段 |
| `adapter/dns.go` | `DNSAnswerObserver` 接口（**极薄**，跨基线友好） |
| `dns/router.go` | `notifyDNSAnswerObservers`（无 observer 即 no-op） |
| 复用 | `promoteLearnedBypass`（M-base，不复制） |

### M-docs-boundary-g

| 路径 |
|------|
| `docs/framework-requirements-boundaries-20260804.md` §边界 G |
| `docs/ebpf-in-out-framework-master-20260803.md` §1.2 |
| `common/ebpf/README.md` Build host |
| 本文 |

---

## 3. 推荐 git 形状（堆叠 / 可切）

```text
(base)  luan/adaptive/<rc>-ebpf-base     ← M-base only（可跟踪 reF1nd 大版本）
   │
   ├─ feature/m-dns-kernel-direct        ← 单模块 PR / cherry-pick
   ├─ feature/m-dns-prefill              ← 单模块 PR / cherry-pick
   └─ feature/m-docs-boundary-g          ← 文档

集成线（可选）:
   feature/ebpf-dns-suite = base + kernel-direct + prefill + docs
```

### 换基线流程（快速合并）

```bash
# 1) 新基线只抬 M-base
git checkout -b adaptive/rcXX-ebpf-base v1.14.0-beta.Y-reF1nd   # 或 reF1nd testing
# 移植/合并历史 eBPF 栈冲突只在这里消化一次

# 2) 功能模块按序 cherry-pick（互不依赖可并行）
git checkout -b feature/m-dns-kernel-direct adaptive/rcXX-ebpf-base
git cherry-pick <M-dns-kernel-direct commits>

git checkout -b feature/m-dns-prefill adaptive/rcXX-ebpf-base
git cherry-pick <M-dns-prefill commits>

# 3) 集成验证（PVE only）
ssh adaptive-pve
cd /root/a51-… && make -C common/ebpf generate check
CGO_ENABLED=1 go test -tags with_ebpf ./common/ebpf ./protocol/ebpf ./include
```

### Commit 消息约定

```
ebpf(M-dns-kernel-direct): …
ebpf(M-dns-prefill): …
docs(M-docs-boundary-g): …
ebpf(M-base): …          # 仅基座
```

便于 `git log --grep='M-dns-prefill'` 与 `cherry-pick`。

---

## 4. 配置面（模块开关，默认全关）

```json
{
  "type": "ebpf",
  "dns_mode": "hijack",
  "dns_kernel_direct": {
    "enabled": true,
    "server_cidr": ["223.5.5.5/32", "119.29.29.29/32"]
  },
  "outbound_offload": {
    "dns_prefill": { "enabled": true, "ttl": "60s" },
    "verdict": { "mode": "off" }
  }
}
```

- 两模块可只开一个。
- `dns_kernel_direct` 要求 `dns_mode=hijack`。
- prefill **不**改路由权威；只 promote；skip fakeip / private / smart 等组出站。

---

## 5. 与「整仓耦合分支」的切割原则

| 要 | 不要 |
|----|------|
| 新逻辑进 `dns_*.go` 独立文件 | 把 DNS 大段塞进 `inbound.go` / `verdict_learn.go` |
| option 用独立 struct | 与 smart/adaptive_pool 字段搅在同一 commit |
| observer 接口放 `adapter` 薄钩子 | DNS router 里写 eBPF 具体 promote |
| 文档模块可单独合 | 文档与内核 map ABI 绑一个 squash |

`inbound.go` 只允许保留：

- 字段：`dnsKernelDirect*` / `dnsPrefill`
- 启动：`normalize*` 调用、`applyDNSKernelDirect()`、`MustRegister[DNSAnswerObserver]`

---

## 6. 当前树状态（实现进度）

| 模块 | 代码 | PVE generate/check | 测试 |
|------|------|--------------------|------|
| M-dns-kernel-direct | ✅ 独立 `dns_kernel_direct.go` + BPF maps | ✅ | ✅ normalize 单测 |
| M-dns-prefill | ✅ 独立 `dns_prefill.go` + observer | ✅（同二进制） | ✅ type 门 + option JSON |
| M-docs-boundary-g | ✅ | n/a | n/a |
| 堆叠分支已推 remote | ❌ 尚未建 `feature/m-*` 远程分支 | — | 本地/build 树已模块化，下一步可 `format-patch` |

### 6.1 优化要点（2026-08-05，无换语言）

| 项 | 做法 |
|----|------|
| DNS Exchange 不堵 | prefill **异步** promote；Exchange 只做过滤+`go` |
| prefill 热路径 | 缓存 Router/OutboundManager；公网过滤+去重后再 walk |
| fakeip | notify **直接 return**，不解析 RR、不回调 |
| 规则正确性 | **按 IP** walk（geoip multi-A）；port=0 避免端口规则误伤 |
| kernel-direct 配置 | 非空 `server_cidr` 即开；`enabled` 无 list → error；去掉死分支 |
| 死 API | 删除未使用的 `DNSDirectMapFDs` |

下一步（需你点头再做）：

1. 从当前 build 树对 M-base 打 `git format-patch` 三段（kernel-direct / prefill / docs）；或  
2. 在 `luan` 上建 `feature/m-dns-kernel-direct` 等并 push。

---

## 7. 版本跟踪备忘

```text
reF1nd 1.14:  … beta.4-reF1nd → beta.5-reF1nd (latest) → (等待 beta.6+/7-reF1nd)
SagerNet   :  … beta.5 → beta.7 (latest) → (无 beta.8)
本产品     :  跟 reF1nd 标签做 M-base 抬升；功能模块不跟大版本号绑定
```
