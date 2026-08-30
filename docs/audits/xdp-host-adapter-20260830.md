# AF_XDP host-adapter implementation audit (2026-08-30)

## Delivered

- `xdp-engine/src/linux_adapter.zig` implements bounded Linux AF_XDP
  UMEM, one XSK per selected queue, RX/TX/fill/completion rings, poll,
  completion recycling, borrowed frame access, and explicit copy/zero-copy
  bind modes.
- `xdp-engine/src/controller.zig` enforces the hand-off order: probe → verified
  program attach → every queue bound → XSKMAP publication → control enable.
- `common/ebpf/native/xdp_runtime.c` rejects control enable until all selected
  XSKMAP slots are present, clears slots on detach, and rejects the current
  unsupported scatter-gather mode.
- The XDP program and probe matrix now keep RX scatter-gather on TC until a
  bounded segment walker exists.

## Verification

GitHub Actions run `33316181921` passed all jobs: Zig tests, Linux
x86_64/aarch64 cross-builds, C ABI smoke check, Go migration tests, BPF syntax,
sections, provenance, and policy-boundary scans. No macOS compilation was
used.

## 115 boundary

The guest currently reports Debian cloud kernel `6.12.100+deb13-cloud-amd64`,
`virtio_net`, two RX/TX queues on `eth0` and `eth1`, and kernel-wide XDP/XSKMAP
support. The device probe reports no XDP program type and `bpftool net` shows
no XDP attachment; only TC `sb_share_in` is active. Therefore 115 is not an
AF_XDP production target yet. Virtio queue count alone is insufficient: a
privileged mode-specific attach, all-queue bind, and bidirectional DIRECT
forwarding test are still required. TC remains the live path.

## Rollback

Do not publish the XDP control record. Leaving `xdp.enabled=false` keeps the
existing v3 TC path unchanged. If a lab attach fails, close the adapter and
detach the program; the C runtime clears XSKMAP entries before returning to TC.
