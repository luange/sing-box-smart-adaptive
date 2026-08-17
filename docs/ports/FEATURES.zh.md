# 功能实现说明（中文）

## 定位

在 **SagerNet 官方 sing-box** 上增加网关向能力，服务 **旁路/PBR + eBPF TC** 场景。

不做：

- reF1nd 整仓覆盖  
- 把官方客户端 GUI 当核心交付物  

## 模块地图

```
cmd/sing-box          官方 CLI
box.go                注册 Hub / Provider / history
protocol/ebpf         eBPF inbound + shared_network + offload
protocol/group        smart / urltest / selector / loadbalance
protocol/group/adaptive  adaptive_pool
protocol/pass         pass 出站
provider/             remote|local|inline + Clash 解析
experimental/connectionhistory
experimental/clashapi /history/*
common/ebpf           CGO/maps/TC 后端
route/conn.go         dial 后 learn/splice 钩子（自有增量）
```

## eBPF 数据面（PBR）

1. **TC 程序**挂在 `include_interface`（如 eth0、pa-*）  
2. **bypass_rule_set** → LPM：命中则内核转发，进程不可见  
3. 未命中 → **socket_assign** 进 userspace `PA-in`  
4. 用户态路由：geoip DIRECT / 区域 smart→trojan 等  
5. DNS hijack + **dns_prefill**：解析结果若稳定 DIRECT → promote TC  

因此：**直连性能看 TC 命中率**；**代理性能看 smart + 日志 + 探测**，不是 DIRECT learn writes。

## Smart vs AdaptivePool

| | Smart | AdaptivePool |
|--|-------|----------------|
| PreMatch unwrap | 有（只读 sticky leaf） | **禁用** |
| 选路时机 | 分数+粘性 | Dial 时 Plan + lease |
| 观测 | dial/字节 | epoch + 业务观测 |
| 网关透明 | 适合 | 完整 L4，不抢 PreMatch |

## 构建 tags

生产网关示例见根目录 `README.md`。缺少 `with_ebpf` 则无 TC/maps；缺少 `with_connection_history` 则无 `/history`。

## 与上游合并

```bash
git fetch sagernet
git merge sagernet/v1.14.0-beta.XX   # 或 cherry-pick
# 冲突优先保留官方行为，再重放 protocol/ebpf、group/smart、provider、history 胶水
```

远程 `sagernet` 指向官方；**无 reF1nd remote**。
