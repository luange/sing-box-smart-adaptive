# W6 · 模块 C.2 可行性结论（routing_mark / bind 下沉）— 2026-08-04

合同：`docs/ebpf-remaining-work-20260804.md` W6；详设 §5.2。

## 问题

能否在 `cgroup/sock_create` 把 `routing_mark` / `bind_interface` 统一打进 socket，
替代 Go 侧逐 dialer 设置，避免“新 dialer 忘记设 mark”类 bug。

## 结论：**不能按 per-outbound 在 sock_create 上做；本项关闭，不进入实现。**

## 理由

1. **`sock_create` 阶段拿不到目标地址**  
   只有 cgroup / uid / 协议族。per-outbound 的 mark 取决于路由结果（目的 IP、规则、
   出站选择），此时 dial 尚未开始，**无法知道**将命中哪个 outbound。

2. **同一进程内多出站共享 socket 身份**  
   sing-box 一个进程内同时存在 DIRECT / 代理 / 组出站。`sock_create` 上所有 TCP
   socket 看起来一样，无法按“将来要走的出站”区分 SO_MARK。

3. **若退化为“进程级统一 mark”**  
   则只能服务“全流量同一 mark”的部署，与当前多 WAN / 分策略出站模型不符，且与
   合同 §193（禁止引入 routing_mark/table 之外的新内核级全局副作用）冲突风险高。

4. **bind_interface 同理**  
   ifindex 绑定同样依赖出站配置，不能在 sock_create 时从目标推断。

## 可选替代（均非本框架 C.2，需单独立项）

| 方案 | 说明 |
|---|---|
| 保持 Go 侧 `DialerOptions` | 现状；用 review / 模板减少漏设 |
| `connect` 程序后期改 mark | 目标地址可见，但改已创建 socket 的 mark/bind 语义脆弱，且与 redirect 路径交互复杂 |
| 每出站 netns / cgroup | 侵入过大，超出 eBPF in/out 框架 |

## 边界确认

- 不引入新 map `sb_out_sockopt`（设计前提不成立）。
- 不改 116 内核；不在 `protocol/direct` 加 wrapper。
- C.3（UDP direct offload）仍冻结（W7）。

## 交付

本文件即 W6 验收要求的“可行性结论（不能做 + 理由）”。**无实现代码。**
