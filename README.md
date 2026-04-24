# Lind Grates

Grates are syscall interceptors for the [Lind](https://github.com/Lind-Project/lind-wasm) WebAssembly runtime. A grate sits between a sandboxed cage process and the kernel, intercepting selected syscalls and handling them with custom logic. Unintercepted syscalls pass through to the kernel normally.

Grates can enforce security policies, emulate devices, add encryption, rate-limit resources, or implement entirely new abstractions — all without modifying the cage program.

## Repository Layout

```
c-grates/                    C grate implementations
  geteuid-grate/             Minimal example — overrides geteuid to return 10
  strace-grate/              Logs all syscalls with arguments and return values
  imfs-grate/                Full in-memory filesystem
  seccomp-grate/             Syscall filter with INI-style allow/deny config
  witness-grate/             Ed25519 signing of syscall arguments

rust-grates/                 Rust grate implementations
  geteuid-grate/             Minimal Rust example
  strace-grate/              Syscall tracer
  imfs-grate/                In-memory filesystem
  chroot-grate/              Path-rewriting chroot jail
  readonly-grate/            Blocks all write syscalls
  write-filter-grate/        Blocks writes to non-.log files
  devnull-grate/             Emulates /dev/null
  resource-grate/            Rate-limiting and resource caps (repy nanny port)
  testing-grate/             Runtime-configurable stub for testing
  namespace-grate/           Routes filesystem syscalls by path prefix
  net-namespace-grate/       Routes network syscalls by port range
  ipc-grate/                 Userspace pipes and unix sockets
  mtls-grate/                Transparent mutual TLS
  fdtables-test-grate/       fdtables stress test

lib/
  grate-rs/                  Rust library for writing grates (GrateBuilder API)

test/
  grates_test.toml           Test suite configuration
  run_tests.sh               Test runner
```

## Quick Start

### Building

```bash
# Build a specific grate
make c/geteuid-grate           # C grate
make rust/strace-grate         # Rust grate

# Build all grates
make all
```

C grates compile with `lind_compile --compile-grate`. Rust grates compile with `cargo lind_compile`. Both output `.cwasm` files to `lindfs/grates/`.

### Running

Grates are the first argument to `lind-wasm`. The cage binary follows:

```bash
# Run a cage through the strace grate
lind-wasm grates/strace-grate.cwasm my-program.cwasm

# Run with a config file (resource grate)
lind-wasm grates/resource-grate.cwasm config.cfg my-program.cwasm

# Compose multiple grates (namespace grate wrapping a resource grate)
lind-wasm grates/net-namespace-grate.cwasm --ports 5432-5432 %{ \
  grates/resource-grate.cwasm rate-limit.cfg \
%} server.cwasm
```

Grate binaries live in `lindfs/grates/`. Cage binaries and config files live in `lindfs/` root.

### Testing

```bash
# Run all tests
make test

# Run tests for one grate
make test GRATE=strace-grate

# List available grates
make list
```

## How Grates Work

### The Grate Pattern

1. **Fork**: The grate forks a child cage process
2. **Register**: The grate registers handler functions for specific syscalls on the child
3. **Exec**: The child execs the cage binary
4. **Intercept**: When the cage makes a registered syscall, the grate's handler runs instead of the kernel
5. **Forward or handle**: The handler can modify arguments, return custom values, or forward to the kernel via `make_threei_call`

### Writing a C Grate

```c
#include <lind_syscall.h>

// Custom handler — return 10 for geteuid
int my_handler(uint64_t cageid) { return 10; }

// Required dispatcher — routes function pointer calls
int pass_fptr_to_wt(uint64_t fn_ptr, uint64_t cageid, ...) {
    int (*fn)(uint64_t) = (int (*)(uint64_t))(uintptr_t)fn_ptr;
    return fn(cageid);
}

int main(int argc, char *argv[]) {
    int grateid = getpid();
    pid_t pid = fork();
    if (pid == 0) {
        register_handler(getpid(), 107, grateid, (uint64_t)&my_handler);
        execv(argv[1], &argv[1]);
    }
    wait(NULL);
    return 0;
}
```

Build: `lind_compile -s --compile-grate --output-dir grates my-grate.c`

### Writing a Rust Grate

```rust
use grate_rs::{GrateBuilder, GrateError};
use grate_rs::constants::SYS_GETEUID;

extern "C" fn my_handler(
    _cageid: u64,
    _arg1: u64, _arg1cage: u64, _arg2: u64, _arg2cage: u64,
    _arg3: u64, _arg3cage: u64, _arg4: u64, _arg4cage: u64,
    _arg5: u64, _arg5cage: u64, _arg6: u64, _arg6cage: u64,
) -> i32 {
    10
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    GrateBuilder::new()
        .register(SYS_GETEUID, my_handler)
        .teardown(|result| println!("done: {:?}", result))
        .run(argv);
}
```

Build: `cargo lind_compile --output-dir grates`

### The grate-rs Library

Rust grates use the `grate-rs` library (`lib/grate-rs/`) which provides:

- **`GrateBuilder`**: Builder pattern for registering handlers and lifecycle hooks
  - `.register(syscall_nr, handler)` — register a syscall handler
  - `.preexec(callback)` — run after fork, before child execs (use for fdtables init)
  - `.teardown(callback)` — run after cage exits
  - `.run(argv)` — fork, register, exec (terminal)
- **`make_threei_call`**: Forward a syscall through the 3i runtime
- **`copy_data_between_cages`**: Copy memory between cage address spaces
- **`is_thread_clone`**: Check if a SYS_CLONE call is a thread (not a fork)
- **`getcageid`**: Get the current cage ID
- **Constants**: Syscall numbers, errno values, file flags, network constants, `GRATE_MEMORY_FLAG`

### Grate Composition

Grates compose by chaining: each grate execs the next one as its child. The namespace grates (`namespace-grate`, `net-namespace-grate`) enable selective composition using `%{ ... %}` syntax:

```bash
# Only route /tmp filesystem calls through the imfs grate
lind-wasm grates/namespace-grate.cwasm --prefix /tmp %{ \
  grates/imfs-grate.cwasm \
%} my-program.cwasm

# Rate-limit only port 5432 traffic
lind-wasm grates/net-namespace-grate.cwasm --ports 5432-5432 %{ \
  grates/resource-grate.cwasm config.cfg \
%} server.cwasm
```

Grates inside `%{ ... %}` handle syscalls that match the condition. Everything else passes through to the kernel. Grates are written independently — the namespace grate handles routing without either grate knowing about the other.

## Contributing

### Directory Structure

C grates go in `c-grates/`, Rust grates in `rust-grates/`:

```
c-grates/<name>-grate/
├── src/
├── test/
├── build.conf
├── compile_grate.sh
��── README.md

rust-grates/<name>-grate/
├── src/
├── test/
├── Cargo.toml
└── README.md
```

### Naming

- Kebab-case: `resource-grate`, `write-filter-grate`
- No `-rs` suffix — the directory location (`rust-grates/`) indicates the language
- Package name in `Cargo.toml` matches the directory name
- Generated `.cwasm` goes to `lindfs/grates/`

### Build Conventions

- C: provide `compile_grate.sh` using `lind_compile -s --compile-grate --output-dir grates`
- Rust: build with `cargo lind_compile --output-dir grates`
- Rust Cargo.toml should use git URLs for `grate-rs` dependency (not path)

### Testing

- Add test programs under `test/`
- Register in `test/grates_test.toml`
- Tests compile with `lind-clang -s` and run as cage binaries
- Use `is_thread_clone` in fork handlers to avoid copying fdtables for threads

### Checklist

- [ ] Grate builds with `make c/<name>` or `make rust/<name>`
- [ ] Tests pass with `make test GRATE=<name>`
- [ ] README documents intercepted syscalls, usage, and build instructions
- [ ] Registered in `test/grates_test.toml`

## Documentation

- [Lind-Wasm documentation](https://lind-project.github.io/lind-wasm/)
- [3i subsystem](https://github.com/Lind-Project/lind-wasm/blob/main/src/threei/README.md)
- [grate-rs API](./lib/grate-rs/src/lib.rs)
