# Lind Grates

Grates are syscall interceptors for the [Lind](https://github.com/Lind-Project/lind-wasm) WebAssembly runtime. A grate sits between a sandboxed cage process and the kernel, intercepting selected syscalls and handling them with custom logic. Unintercepted syscalls pass through to the kernel normally.

Grates can enforce security policies, emulate devices, add encryption, rate-limit resources, or implement entirely new abstractions — all without modifying the cage program.

## Repository Layout

```
c-grates/           C grate implementations
rust-grates/        Rust grate implementations
lib/grate-rs/       Rust library for writing grates
test/               Test suite configuration and runner
```

See [issue #6](https://github.com/Lind-Project/lind-wasm-example-grates/issues/6) for the current status of implemented grates.

## Quick Start

### Building

```bash
# Build a specific grate
make c/geteuid-grate           # C grate
make rust/strace-grate         # Rust grate

# Build all grates
make all
```

C grates compile with `lind_compile --compile-grate`. Rust grates compile with `cargo lind_compile`. Both output `.cwasm` files to `lindfs/`.

### Running

A grate is run as a regular Lind program. The grate takes the target cage binary as input. Each grate has its own usage — see the individual grate's README for details.

```bash
lind-wasm grates/strace-grate.cwasm my-program.cwasm
```

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

### Grate Lifecycle

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
        // register_handler(target_cage, syscall_number, grate_id, handler_fn_ptr)
        //   target_cage:    cage ID to intercept syscalls from
        //   syscall_number: which syscall to intercept (e.g. 107 = geteuid)
        //   grate_id:       this grate's cage ID (for routing)
        //   handler_fn_ptr: address of the handler function
        register_handler(getpid(), 107, grateid, (uint64_t)&my_handler);
        execv(argv[1], &argv[1]);
    }
    wait(NULL);
    return 0;
}
```

Build: `lind_compile -s --compile-grate my-grate.c`

### Writing a Rust Grate

Rust grates can optionally use the `grate-rs` library (`lib/grate-rs/`) which provides a `GrateBuilder` API that handles the fork/register/exec lifecycle. See [`lib/grate-rs/README.md`](./lib/grate-rs/README.md) for the full API documentation.

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

Build: `cargo lind_compile`

### Grate Composition

Grates compose by chaining — each grate execs the next one as its child. This allows stacking multiple interposition layers without any grate needing to know about the others.

For selective composition, namespace grates can route specific syscalls to a clamped grate based on a condition (path prefix, port range, etc.) while passing everything else through to the kernel. See the namespace grate READMEs for usage details.

## Contributing

### Directory Structure

C grates go in `c-grates/`, Rust grates in `rust-grates/`:

```
c-grates/<name>-grate/
├── src/
├── test/
├── build.conf
├── compile_grate.sh
└── README.md

rust-grates/<name>-grate/
├── src/
├── test/
├── Cargo.toml
└── README.md
```

### Naming

- Kebab-case: `resource-grate`, `write-filter-grate`
- The directory location (`c-grates/` or `rust-grates/`) indicates the language
- Package name in `Cargo.toml` matches the directory name

### Build Conventions

- C: provide `compile_grate.sh` using `lind_compile -s --compile-grate`
- Rust: build with `cargo lind_compile`
- Use `--output-dir grates` if you want the output in `lindfs/grates/` instead of `lindfs/`

### Testing

- Add test programs under `test/`
- Register in `test/grates_test.toml`
- Tests compile with `lind-clang -s` and run as cage binaries

### Checklist

- [ ] Grate builds with `make c/<name>` or `make rust/<name>`
- [ ] Tests pass with `make test GRATE=<name>`
- [ ] README documents intercepted syscalls, usage, and build instructions
- [ ] Registered in `test/grates_test.toml`

## Documentation

- [Lind-Wasm documentation](https://lind-project.github.io/lind-wasm/)
- [3i subsystem](https://github.com/Lind-Project/lind-wasm/blob/main/src/threei/README.md)
- [grate-rs library](./lib/grate-rs/README.md)
