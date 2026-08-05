# Feature module branches (`luan` remote)

| Branch / tag | Module | Primary paths |
|--------------|--------|----------------|
| `feature/m-dns-suite` · `m-dns-suite` | all | full lab stack |
| `feature/m-dns-kernel-direct` · `m-dns-kernel-direct` | M-dns-kernel-direct | `protocol/ebpf/dns_kernel_direct*.go`, option `dns_kernel_direct`, `common/ebpf` dns_direct maps + BPF `:53` |
| `feature/m-dns-prefill` · `m-dns-prefill` | M-dns-prefill | `protocol/ebpf/dns_prefill.go`, `adapter/dns.go` observer, `dns/router.go` notify |
| `feature/m-docs-boundary-g` · `m-docs-boundary-g` | docs G/H | `docs/ebpf-feature-modules-*.md`, `docs/framework-requirements-boundaries-*.md` |
| `adaptive/rc32-ebpf-dns` | alias of suite | production tracking name |

All `feature/m-dns-*` branches currently share the same tip (one green atomic suite).
Prefer merging **suite** onto a new M-base; split only when rebasing to a newer reF1nd tag.

```bash
git fetch luan
git checkout feature/m-dns-suite
# module tags
git checkout m-dns-prefill
```

Details: `docs/ebpf-feature-modules-20260805.md`.
