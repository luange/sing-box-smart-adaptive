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
`builtin_ai_service_tls` 改为五个相互隔离的服务探测：YouTube TLS、跟随 Google
可达性的 Gemini TLS、不带凭据的 OpenAI/Anthropic 模型列表请求，以及浏览器形态
的 ChatGPT 网页/WAF 请求。无认证 API 的 HTTP 401 表示链路可达；网页探测的 2xx
表示可达，HTTP 403/451 或 `cf-mitigated: challenge` 写入受阻证据。只有严格多数
节点同类失败才作为共同目标故障，5xx 不惩罚节点。请求不会持久化 API key、Cookie、
响应头或查询参数。内置模式每个服务只有一个
目标，因此必须使用 `quorum: 1`；两个内置模式和签名 manifest 模式互斥。

磁盘孤儿状态使用 `sing-box tools adaptive-state-gc` 检查，默认只 dry-run；确认
所有 active state stem 均已传入后才可使用 `--apply`。Firefox 独立代理验收工具
位于 `test/validation/adaptive_pool_firefox_acceptance.py`。
