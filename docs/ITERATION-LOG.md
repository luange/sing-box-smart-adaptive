# Iteration log

## 2026-08-13 — beta14 Smart tcv2.21 reproducible build

- Functional tag: `v1.14.0-beta.14-smart-tcv2.21`
- Functional commit: `128a71122c`
- CI reproducibility commits: `66773b7e66`, `853621c586`
- Reviewed branch: `adaptive/beta12-smart-mem9`
- Artifact version: `1.14.0-beta.14-smart-tcv2.21-853621c5`
- GitHub Actions run: `31664128012`
- Release tag: `adaptive-1.14.0-beta.14-smart-tcv2.21-853621c5`
- Linux AMD64 SHA256:
  `5dbfe18ce479c5af26e332a9adcfbe4ac75f5794de90260a70165810449b2530`
- Linux ARM64 SHA256:
  `97e9846b8507c9f89127cb7391e575d0a1e48c55a2bc1f365fe3298f433805ee`
- Build tags include both `with_tailscale` and `with_wireguard`.
- CI result: adaptive tests, AMD64 build, ARM64 build, packaging, checksums,
  and GitHub prerelease all passed.
- Merge policy: keep local Smart/AdaptivePool/eBPF conflict components; prefer
  upstream for general components; do not splice the conflicting upstream
  cgroup/shared-network eBPF stack into the local data plane.
- Deployment: QNAP uppercase and lowercase QPKGs use the ARM64 artifact;
  `singbox-smart-lxd` was updated offline and remains stopped; `smbox-lxd` was
  not modified.
- Business gates observed after deployment: Google 204, YouTube 200, and both
  lowercase-QPKG SOCKS entries returned Google 204.
- Network boundary: default route and resolver configuration were not changed.
- Limitation: long-duration production gates remain separate from successful
  build and immediate business validation.

