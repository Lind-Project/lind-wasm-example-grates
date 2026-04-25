# fs-view-grate

Provides per-cage filesystem isolation by transparently prefixing all paths
with `/cage-<id>/`. Each cage sees its own filesystem namespace — two cages
opening `/tmp/foo` access completely independent files.

Designed to be composed with imfs-grate or any filesystem grate:

```bash
lind-wasm grates/namespace-grate.cwasm --prefix /tmp %{ \
  grates/fs-view-grate.cwasm \
  grates/imfs-grate.cwasm \
%} my-program.cwasm
```

Cage 3 opening `/tmp/foo` → fs-view rewrites to `/cage-3/tmp/foo` → imfs stores it.
Cage 4 opening `/tmp/foo` → fs-view rewrites to `/cage-4/tmp/foo` → independent file.

## Intercepted syscalls

open, stat, access, mkdir, rmdir, unlink, unlinkat, chmod, truncate,
chdir, readlink, rename, link, fork, exec

## Building

```bash
cd rust-grates/fs-view-grate
cargo lind_compile --output-dir grates
```
