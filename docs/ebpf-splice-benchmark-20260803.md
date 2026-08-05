# eBPF splice 基准（2026-08-03 / rc44c-fw，lab 112）

合同 D-4：声称收益必须用 iperf/CPU 量化；curl 小对象墙钟不作收益证据。

## 环境

| 项 | 值 |
|---|---|
| 客户端 | 112 `ebpf-splice-lab` 10.30.0.219，Debian 13，~1 vCPU / 1 GiB |
| 服务端 | PVE 10.20.20.3 `iperf3 -s -p 5201` |
| 二进制 | `1.14.0-beta.4-reF1nd-luan-adaptive.rc44c-fw` |
| 路径 | capture_local → eBPF inbound → DIRECT → PVE |
| splice ON | `half_close=close`，日志 `eBPF splice pair active` |
| splice OFF | `half_close=passthrough`，日志 `splice skip: half_close=passthrough`（用户态 copy） |
| 切换方式 | 改 `/root/singbox/config.json` → `singbox-build-runtime-config` → `systemctl restart`（**仅 SIGHUP 不会重建 runtime 配置**） |

## 功能门槛（仍成立）

| 指标 | 结果 |
|---|---|
| HTTP E2E | capture → DIRECT → `:18080` `pve-ok` 20/20 + reload 后 20/20 |
| pair | ON 时 `pair active`；OFF 时 skip passthrough |
| fail-open | 未 Activate 的 Release 不关 socket（rc44c 修） |

## iperf3 吞吐 / CPU

CPU% = 测试窗口内 `sing-box` 进程 user+sys jiffies / 墙钟（单核约等于占用比例）。

### 上行（client → server）

| 模式 | 时长 | 吞吐 (receiver) | sing-box CPU% | 日志 |
|---|---|---|---|---|
| **splice ON** (`close`) | 10 s | **15.5 Gbits/s** | **14.0%** | `pair active` |
| splice OFF (`passthrough`) | 10 s | 12.9 Gbits/s | 52.2% | `skip: half_close=passthrough` |

相对用户态 copy：吞吐 **+20%**，CPU **约 −73%**（52→14）。

### 下行（server → client，`iperf3 -R`）

| 模式 | 时长 | 吞吐 (receiver) | sing-box CPU% | 日志 |
|---|---|---|---|---|
| **splice ON** | 6 s | **13.5 Gbits/s** | **15.1%** | （低 CPU，与 ON 一致） |
| splice OFF | 6 s | 12.0 Gbits/s | 48.0% | `skip: half_close=passthrough` |

相对用户态：吞吐 **+12.5%**，CPU **约 −69%**（48→15）。

### 备注

1. 两机均为 virt 网桥路径，绝对值受宿主机调度影响；**同路径 A/B 对比**有效。  
2. 112 内存 ~1 GiB，长时 30s + 大 JSON 曾 OOM；正式矩阵用 6–10s 文本输出。  
3. 早期一次 30s ON 曾见 ~4.6 Gbits/s（reload/健康检查风暴叠加），以清理 restart 后的 10s/6s 矩阵为准。  
4. iperf3 控制连接 + 数据连接各一条，ON 时可见两次 pair/skip 属预期。

## 是否进入模块 A（P1）

| 条件 | 状态 |
|---|---|
| B 功能验收 | ✅ |
| 可测量吞吐/CPU 收益 | ✅ **有**（上行 +20% 吞吐、CPU 约 1/4） |
| 建议 | 模块 B 可保留默认关、lab/网关按需开；**P1 verdict 不再被「无收益证据」阻塞**。开工仍需用户显式批准 + 安全门。 |

## 配置

```json
"outbound_offload": {
  "splice": {
    "enabled": true,
    "accounting": true,
    "half_close": "close",
    "allow_outbound_types": ["direct"]
  },
  "verdict": { "mode": "off" }
}
```

## 复现命令（112）

```bash
# PVE
iperf3 -s -B 0.0.0.0 -p 5201

# 112 — ON
# half_close=close in config.json + build-runtime + restart
iperf3 -c 10.20.20.3 -p 5201 -t 10
iperf3 -c 10.20.20.3 -p 5201 -t 6 -R

# OFF: half_close=passthrough 后同上
```
