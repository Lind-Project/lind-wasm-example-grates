# Shared mmap on `/tmp` Demo

Demonstrates postgres-style dynamic shared memory (DSM) across multiple
cooperating cages using two composed grates:

- **fs-routing-clamp**: routes `/tmp` paths to the clamped grate stack
- **imfs-grate**: in-memory filesystem (shared across all cages — no
  per-cage view layered on top)

A parent cage creates a file under `/tmp`, ftruncates it to one page,
mmaps it `MAP_SHARED`, and forks two children. Each child opens the
same path independently, mmaps it, and stamps a marker at its own
offset. The parent then verifies it sees all three markers (its own +
both children's) through its mapping — confirming all three cages
genuinely share the same backing pages.

This is the exact pattern postgres uses when worker processes attach
to a DSM segment by name. The key distinction vs.
`test_mmap_shared_fork` is **N ≥ 3 cooperating processes**: it's not
enough to verify one fork sees the parent's writes; we need multiple
forked children each independently calling `mmap()` and the parent
observing all of their writes.

## What it tests

1. **Parent's own write is visible to itself via the mapping** after the
   children stamp their markers (nobody clobbers offset 0).
2. **Each child's independent mmap of the same path** lands on the same
   imfs-backed pages.
3. **All three writes coexist** in the segment.

## Running

```bash
bash demos/mmap-shared-tmp/build.sh
bash demos/mmap-shared-tmp/run.sh
```

## Composition rationale

No `fs-view-grate` layered between the clamp and imfs — we *want* the
cages to share the same imfs (per-cage isolation would defeat the
purpose of testing shared mmap). The clamp is here so `/tmp` paths
route through imfs while everything else still hits the host FS.
