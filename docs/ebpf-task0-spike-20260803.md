# 任务 0 Spike 实测（2026-08-03，lab 112）

合同：`docs/ebpf-outbound-framework-plan-20260803.md` §3.1 三问。  
环境：Debian 13 cloud `6.12.96+deb13-cloud-amd64`，`CONFIG_BPF_STREAM_PARSER=y`，`CONFIG_NET_SOCK_MSG=y`。

## 1. `remote_port` / `local_port` 字节序

| 字段 | 观测 | 落地 |
|---|---|---|
| `local_port` | host order 的 u16（低 16 位有效） | Go `TCPAddr.Port` 同 host order，直接写入 key |
| `remote_port` | u32，**网络序端口在高 16 位**（LE 下 `>>16` 再 `bswap16` → host） | `splice.bpf.c` `fill_splice_ports` |

证据：pair 后 `peer_misses=0` 且 `redirects>0`；若端口序错必然 peer miss 或双向不通。  
静态断言：`splice.bpf.c` 要求 `__BYTE_ORDER__ == LITTLE_ENDIAN`。

## 2. ESTABLISHED socket 入 SOCKHASH

| 场景 | 结果 |
|---|---|
| 已 `Dial`/`Accept` 的 ESTABLISHED TCP | `BPF_MAP_UPDATE_ELEM` 成功（lab 日志 `eBPF splice pair active`） |
| MPTCP listen/accept（Go 1.24 默认） | SOCKMAP 更新 `EOPNOTSUPP` → tproxy/eBPF 监听强制 `SetMultipathTCP(false)` |
| 非 ESTABLISHED | 未在 lab 强测；内核预期 `EINVAL`/`EOPNOTSUPP`，Pair 失败 → fail-open |

## 3. sockmap 后 EPOLLRDHUP

| 项 | 结果 |
|---|---|
| `epoll_ctl(EPOLLRDHUP\|HUP\|ERR)` 加在 pair 两端 | attach 成功 |
| 对端关闭 | watchdog/epoll 路径 `Release()`，metrics `pairs.released` 递增 |
| 结论 | P0 关闭方案可用 EPOLLRDHUP + idle watchdog；**暂不需要** sock_ops+ringbuf |

## 4. 附加：flags=0 vs INGRESS

| flags | 语义 | 实测 |
|---|---|---|
| `0` | `tcp_bpf_sendmsg_redir` 经对端发到网络 | HTTP 200 E2E |
| `BPF_F_INGRESS` | 塞进对端 recv queue（sidecar） | 文档已纠正；未再上线 |

## 5. 116 对比（负证据）

Alpine `linux-virt`：`# CONFIG_BPF_STREAM_PARSER is not set` → STREAM_* attach `EOPNOTSUPP`。  
verdict-only（attach type=10）运行时探测保留；116 此前仍失败。**不改 116 内核。**
