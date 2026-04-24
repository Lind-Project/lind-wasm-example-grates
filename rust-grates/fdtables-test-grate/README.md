# fdtables-test-grate

Stress test for the `fdtables` crate under Lind's WASM runtime. Exercises
fdtables operations (translate, get_specific, close, copy) under single-cage
and cross-fork scenarios to isolate threading and DashMap issues from
grate-specific logic.

## What it tests

All handlers do fdtables bookkeeping and forward the real syscall. The grate
itself has no policy — it just tracks fds.

**Mutex / atomic contention probes**: The write handler increments three
counters on every write to fd > 2:
- `MUTEX_COUNT` — under `std::sync::Mutex`
- `ATOMIC_COUNT` — with `AtomicU64::fetch_add`
- `UNSYNC_COUNT` — plain load+store (deliberate race, control group)

After fork, both parent and child write through the grate, hitting the
counters from different runtime workers. Reading from magic fd 99 reports
the counter values. If Mutex works cross-thread, all three match. If not,
`MUTEX_COUNT < ATOMIC_COUNT` (lost updates).

## Intercepted syscalls

| Syscall | fdtables operation |
|---------|-------------------|
| open | `get_specific_virtual_fd` on success |
| close | `translate_virtual_fd` + `close_virtualfd` |
| dup | `translate_virtual_fd` + `get_specific_virtual_fd` |
| dup2 | `translate_virtual_fd` + `get_specific_virtual_fd` |
| read | `translate_virtual_fd` (fd 99 = counter report) |
| write | `translate_virtual_fd` + contention counters |
| fork | `copy_fdtable_for_cage` |
| exec | `empty_fds_for_exec` + reserve fds 0-2 |

## Usage

```bash
lind-wasm grates/fdtables-test-grate.cwasm fdtables_test.cwasm
```

## Building

```bash
cd examples/fdtables-test-grate
cargo lind_compile --output-dir grates
lind-clang -s test/fdtables_test.c
```
