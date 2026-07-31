# AdaptivePool 发布门禁

完整报告：

`/Users/luan/Documents/Codex/2026-07-17/new-chat-3/outputs/adaptive-release-gates-20260730.md`

```sh
./scripts/run-adaptive-release-gates.sh
```

## 本机结果（2026-07-30）

- 功能门禁 G1–G10：**PASS**（含 `-race`）
- **Heap 1000 reload（G11）：PASS**
  - `heap_inuse`：**+48 KiB**（预算 24 MiB）
  - goroutine：2 → 2
  - profiles：`outputs/adaptive-heap-gate-20260730/`

历史 RSS 52→98MB **不是** Adaptive 控制面在本门禁下的表现；全进程 RSS 需 packaged binary 另测。
