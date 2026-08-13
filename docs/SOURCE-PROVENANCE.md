# Source provenance and dual-copy policy

This repository keeps one Git history and two local working copies. The copies
are not independent sources of truth: commits and tags are the synchronization
boundary.

## Canonical locations

- Build and Claude review copy:
  `/Volumes/WeChat/CodexBuild/sing-box-beta14-smart-tcv2.21`
- Codex review copy:
  `/Users/luan/Documents/Codex/2026-06-18/version-3-9-services-sub-store/work/a53-beta14-smart-tcv2.21-review`
- Published repository:
  `https://github.com/luange/sing-box-smart-adaptive`

Never copy a dirty worktree over the other copy. Commit the change, push the
branch, then fast-forward the second copy to the exact same commit. Before a
review or build, both copies must report the same value from `git rev-parse
HEAD` and both must have an empty `git status --porcelain`.

## Upstream lineage

- Product fork: `https://github.com/luange/sing-box-smart-adaptive`
- reF1nd base: `https://github.com/reF1nd/sing-box.git`
- SagerNet upstream: `https://github.com/SagerNet/sing-box.git`

Upstream changes are merged by Git. Smart, AdaptivePool, and the project eBPF
data plane keep the local implementation when a conflict is classified in
those modules. General upstream files prefer upstream. A deleted file is
treated as a deletion rather than blindly checking out a missing merge side.

## Required iteration record

Every functional iteration must record:

1. base commit/tag and relevant upstream commit;
2. resulting commit and release tag;
3. functional changes and intentionally disabled features;
4. tests, race tests, deterministic fault injection, and real-business gates;
5. binary architecture, build tags, SHA256, and GitHub Actions run;
6. deployment targets, configuration changes, rollback object, and outcome;
7. known limitations and unfinished release gates.

Binary backups belong in the NAS content-addressed core repository. They must
not be duplicated in space-constrained VMs.
