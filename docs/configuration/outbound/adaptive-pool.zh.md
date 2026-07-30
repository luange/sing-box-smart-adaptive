# AdaptivePool

AdaptivePool 是独立于 sing-box 官方数组布局的出站决策模块。官方 provider
变化只在 `source_a48_v1` 反腐层取值；核心只处理 canonical snapshot/delta、
稳定 `NodeHandle`、健康证据和 epoch-local 执行绑定。

建议先使用 `"shadow": true`。只有 generation 非零、候选数与 active binding
一致、scheduler owner 有效、missed observation 为零且资源没有单调增长时才
能切换到承载流量。这个过程不要求修改网关或统一 DNS。

旧 Smart 配置使用 `sing-box tools adaptive-migrate` 迁移。工具会先生成原文件
逐字节回滚副本，再输出默认 shadow 的 AdaptivePool 配置；无法等价迁移的旧
参数会列出字段名，不会静默伪装成已支持。

动态 YouTube/媒体地址必须由 HTTPS Ed25519 签名 manifest 提供，URL、query、
token 不得进入状态、日志、错误和持久化。密钥用
`sing-box generate adaptive-manifest-key` 生成，服务用
`sing-box tools adaptive-manifest serve` 启动；私钥文件必须为 0600。

能力探测支持 `tls`、`auth_http`、`http`、`http3`、`range`。`http3` 仅在 `with_quic`
构建启用，并明确拒绝 HTTP/2 回退。Clash API 在 `/adaptive-pools/v1` 提供状态、
探测、服务覆盖和 SSE 事件；代理对象也包含 generation、revision、lease、队列、
breaker、吞吐和 evidence 字段。

`builtin_youtube_tls` 启用固定且不含凭据的 YouTube TLS 目标。
`service_qualification` 启用五个相互隔离的服务资格探测：YouTube TLS、跟随 Google
可达性的 Gemini TLS、不带凭据的 OpenAI/Anthropic 模型列表请求，以及浏览器形态
的 ChatGPT 网页/WAF 请求。无认证 API 的 HTTP 401 表示链路可达；网页探测的 2xx
表示可达，HTTP 403/451 或 `cf-mitigated: challenge` 写入受阻证据。只有严格多数
节点同类失败才作为共同目标故障，5xx 不惩罚节点。请求不会持久化 API key、Cookie、
响应头或查询参数。内置模式每个服务只有一个
目标，因此必须使用 `quorum: 1`；两个内置模式和签名 manifest 模式互斥。

## 人工节点策略

`exclude_nodes` 用于按完整节点名或关键词剔除已知不可用节点。以 `=` 开头表示
忽略大小写的完整匹配，其他值表示忽略大小写的关键词包含匹配。`exclude` 和
`include` 仍然是分组边界上的正则过滤器。

`node_weights` 只改变合格候选之间的偏好：小于 `1` 为降低权重，`1` 为中性，
大于 `1` 为提高权重。它不能让已排除、不健康、服务不兼容或断路器打开的节点
重新入选。完整名规则以 `=` 开头；多个关键词同时命中时使用最长规则，完整名
规则始终优先。状态 API 会逐节点返回 `weight`、`weight_rule` 和
`weight_rule_exact`，可直接确认规则是否真正生效。

服务租约和切换审计会返回16位十六进制 `session_id`。它只是用于关联同一个
匿名客户端/服务亲和会话的截断带密钥摘要，不包含源地址、进程、用户名、目标、
token或凭据。

示例：

```json
{
  "type": "adaptive_pool",
  "tag": "US",
  "providers": ["airport"],
  "exclude_nodes": ["=airport/已退役节点"],
  "node_weights": [
    { "match": "Gcore", "weight": 0.25 },
    { "match": "=airport/优选节点", "weight": 2.0 }
  ],
  "capability": {
    "enabled": true,
    "service_qualification": true,
    "builtin_exit_identity": true,
    "refresh_interval": "10m",
    "timeout": "120s",
    "quorum": 1
  },
  "policy": {
    "default": "adaptive",
    "ai_ipv6_policy": "block"
  }
}
```

`service_qualification` 默认关闭，可以在任意地区或用途的 AdaptivePool 中单独开启。
资格证据以“节点 + 服务”隔离：例如 ChatGPT 受阻只阻止该节点承载 ChatGPT，节点仍可
承载普通网页、YouTube、Claude 或其他服务。关闭参数时不创建资格探测控制器，也不会
读取先前进程的资格结果。

Apple和Microsoft OAuth域名会与ChatGPT、Claude、Gemini、Google登录及
Cloudflare challenge共用 `browser_identity` 租约。

`policy.ai_ipv6_policy` 支持 `allow`（默认）和 `block`。`block` 会拒绝已识别为
ChatGPT/OpenAI、Claude、Gemini、Google/Apple/Microsoft登录或Cloudflare challenge的IPv6
目标，使双栈客户端回落到 IPv4；非 AI 的 IPv6 业务不受影响。这个参数只是
安全门禁，不能代替把 IPv6 流量正确纳入透明代理/PBR。

`builtin_exit_identity` 复用同一个 scheduler 和 ObservationIngestor -> Reducer，
分别探测 IPv4、IPv6 出口。原始公网地址只会转换成进程内带密钥摘要，不会进入
API、日志或持久化。状态会显示 IPv4 基线、IPv6 基线、双栈节点、身份变化及
轮换饱和节点；sing-box 进程退出后所有身份基线自动失效。

磁盘孤儿状态使用 `sing-box tools adaptive-state-gc` 检查，默认只 dry-run；确认
所有 active state stem 均已传入后才可使用 `--apply`。Firefox 独立代理验收工具
位于 `test/validation/adaptive_pool_firefox_acceptance.py`。
