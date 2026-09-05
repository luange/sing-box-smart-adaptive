# 聚合 Provider

`aggregate` Provider 将多个已有的 outbound Provider 组合成一个只读视图。子 Provider
仍然可以单独被 Smart、URLTest、Balance 或其它组引用；聚合 Provider 只是复用它们已经
创建的 outbound，不会重复下载、解析、创建连接或复制健康画像。

```json
{
  "providers": [
    { "type": "remote", "tag": "airport-a", "url": "https://example/a" },
    { "type": "remote", "tag": "airport-b", "url": "https://example/b" },
    { "type": "remote", "tag": "airport-c", "url": "https://example/c" },
    {
      "type": "aggregate",
      "tag": "all-airports",
      "providers": ["airport-a", "airport-b", "airport-c"]
    }
  ],
  "outbounds": [
    {
      "type": "smart",
      "tag": "smart-all",
      "providers": ["all-airports"]
    },
    {
      "type": "urltest",
      "tag": "airport-a-only",
      "providers": ["airport-a"]
    }
  ]
}
```

聚合结果按子 Provider 配置顺序展开，使用子 Provider 已有的稳定 outbound tag；重复
tag 只保留第一次出现的对象并记录警告。`include` 和 `exclude` 可在聚合层做最终过滤。
子 Provider 更新时，聚合 Provider 会增量通知引用它的组。删除或暂停聚合 Provider 不会
影响仍被独立引用的子 Provider。

不允许循环引用，例如 `all -> hk -> all`；循环会在启动阶段明确报错。聚合 Provider
不拥有子 Provider 的生命周期，因此不会在关闭时重复关闭或删除子 Provider。
