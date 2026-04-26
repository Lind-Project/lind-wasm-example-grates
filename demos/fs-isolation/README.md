# Filesystem Isolation Demo

Demonstrates per-cage filesystem isolation using three composed grates:

- **fs-routing-clamp**: Routes `/tmp` paths to the clamped grate stack
- **fs-view-grate**: Prefixes paths with `/cage-<id>/` for per-cage isolation
- **imfs-grate**: Provides an in-memory filesystem

Paths under `/tmp` are routed to an in-memory filesystem, with each cage
getting an independent view via path prefixing. All other paths proceed
to the host filesystem normally.

Two cages that both open `/tmp/foo` receive independent in-memory files with
no shared state. This cannot be replicated with FUSE (requires privileged mount)
or mount namespaces (cannot route different prefixes to different backing stores
within the same process tree).

## What it tests

1. **Independent /tmp per cage**: Parent writes "parent-data" to `/tmp/foo`,
   child writes "child-data" — each sees only its own data
2. **Multiple files isolated**: Parent creates `/tmp/a.txt` and `/tmp/b.txt`,
   child cannot see either
3. **Non-/tmp paths shared**: Host filesystem paths like `/dev/null` work
   normally for all cages

## Running

```bash
bash demos/fs-isolation/build.sh
bash demos/fs-isolation/run.sh
```
