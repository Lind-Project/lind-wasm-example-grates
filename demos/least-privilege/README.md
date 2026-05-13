# Least-Privilege Confinement Demo

Demonstrates confining a process tree to `/workspace` using three
independently-written grates composed together:

- **seccomp-grate**: Denies all filesystem syscalls with EPERM by default
- **fs-routing-clamp**: Routes `/workspace` paths to the imfs-grate
- **imfs-grate**: Provides an in-memory filesystem for `/workspace`

The test program forks child processes at multiple depths and verifies
that `/workspace` access works while `/etc`, `/home`, and `/tmp` are
denied with EPERM from every spawned cage.

## Running

```bash
# Build the grates
make c/seccomp-grate
make rust/fs-routing-clamp
make rust/imfs-grate

# Compile the test
lind-clang -s demos/least-privilege/least_privilege_test.c

# Run
bash demos/least-privilege/run.sh
```
