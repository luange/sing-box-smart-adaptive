# eBPF 实用缺口与 dae 对齐补强（2026-08-04）

原则：**稳定 > 性能数字**；**高触发率**（生产网关真实流量会命中）优先于实验室低触发特性。

## 缺口分层

### A. 已补（本轮代码）

| 缺口 | 原因 | 补法 |
|------|------|------|
| 网关 learn 后仍进用户态 | verdict 只在 **connect4**；TC shared_network 只认 **CIDR LPM** | learn 成功后 **promote /32 → TC bypass**（`promote_bypass`，learn 默认 true） |
| learn 一直 skip 难排查 | 只有总 skips | 周期日志 **skip reasons**（sniff/match、non_direct、…） |
| 路由顺序导致 MatchInputs 污染 | protocol/domain 在 IP DIRECT 前 | 配置顺序（生产已改） |

### B. 高触发、稳、已具备（配置即可）

| 项 | 说明 |
|----|------|
| `bypass_rule_set: geoip-cn` | 与 dae「规则直连」同档；生产主红利 |
| IP DIRECT 在 sniff/protocol 前 | learn / promote 前提 |
| splice allow direct/ebpf/socks/http | 透传高触发；不 peel 加密 |
| RFC1918 TC builtin bypass | 防环；局域网不进代理数据面 |

### C. 明确不做 / 低触发（冻结）

| 项 | 理由 |
|----|------|
| DNS prefill / 域名 TC 引擎 | 触发依赖 DNS 形态，稳性与灵活度差 |
| 协议 peel（SS/trojan/vless splice） | 低稳、低通用；dae 也不拆 AEAD |
| UDP offload C.3 | 已冻结 |
| 私网 VM 测 PA userspace | builtin bypass，测不出网关真实路径 |

### D. 后续可选（仍要高触发才做）

1. promote 条目带 generation，与 verdict 同失效（今日 invalidate 已 clear promoted）
2. promote 指标：promoted_count / promote_refresh_err（日志已有）
3. 更多纯 CIDR bypass 包（非 geosite 域名集）

## dae 对照（搬什么、不搬什么）

| dae | 本栈 | 决策 |
|-----|------|------|
| 控制面判定 + 数据面 direct | route DIRECT + bypass/promote | ✅ 搬语义 |
| 内核不再见 direct 流 | TC LPM bypass | ✅ |
| 全量规则进 eBPF | 不做 | 稳性/维护成本 |
| 代理路径内核加速 | splice bare TCP only | ✅ 同级 |

## 配置

```json
"outbound_offload": {
  "verdict": {
    "mode": "learn",
    "ttl": "5m",
    "promote_bypass": true
  },
  "splice": { "enabled": true, "allow_outbound_types": ["direct","ebpf","socks","http"] }
},
"bypass_rule_set": ["geoip-cn"]
```

`promote_bypass` 省略时：mode=learn → true；mode=off → false。

## 安全

- 仅 promote **非 RFC1918** 公网 IP（私网已 builtin）
- 上限 8192 条；TTL 到期剔除；InvalidateAll / iface 变更 clear
- fail-open：promote refresh 失败只打 Debug，不影响连接
