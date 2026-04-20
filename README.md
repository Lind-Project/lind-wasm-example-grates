# Example Grates for Lind

This reposistory contains a collection of example grate implementations that can be used with the [Lind runtime](https://github.com/Lind-Project/lind-wasm)

Grates provide custom syscall wrappers for Lind cages. Each example grate here demonstrates how to override one or more syscalls with a custom implementation.

For more details, refer to the documentation here:

- [Lind-Wasm documentation](https://lind-project.github.io/lind-wasm/)
- [3i](https://github.com/Lind-Project/lind-wasm/blob/main/src/threei/README.md)

## Repository Structure

Each directory under `examples/` contains a standalone grate implementation.

For a grate written in `C`, the typical structure for an individual grate is:

```
examples/<name>-grate
├── src/                // .c and .h source files.
├── test/               // Tests for this grate.
├── build.conf          // Configuration file to describe additional build flags, `--max-memory` for wasm, and entry point for the grate.
├── compile_grate.sh    // Compile script to generate *.wasm and *.cwasm binaries
└── README.md
```

## Writing a Grate

By default, syscalls invoked by a cage are forwarded to `rawposix`. A grate allows selected syscalls from a child cage to be intercepted and handled by custom functions.

Using the example in `examples/geteuid-grate` to illustrate this process:

**Registering Syscall Handlers:**

First, define a custom implementation of the syscall.

```c
int geteuid_grate(uint64_t cageid) {
    return 10;
}
```

Next, register this function as the handler for `geteuid` using the `register_handler` function

```c
// Fork a child process
pid_t pid = fork();
if (pid == 0) {
    int cageid = getpid();

    // Register our custom handler
    uint64_t fn_ptr_addr = (uint64_t)(uintptr_t_) &geteuid_grate;
    register_handler(cageid, 107, 1, grateid, fn_ptr_addr);

    // Run the cage (provided as argv[1])
    execv(argv[1], &argv[1]);
}
```

**Dispatch Handling:**

Each grate must define a dispatcher function named `pass_fptr_to_wt` which serves as the entry point for all intercepted syscalls in that grate.

The dispatcher is invoked with:
- Function pointer registered for this syscall,
- Calling cage id,
- Syscall arguments (and their associated cage IDs)

```c
int pass_fptr_to_wt(uint64_t fn_ptr_uint, uint64_t cageid, uint64_t arg1,
                    uint64_t arg1cage, uint64_t arg2, uint64_t arg2cage,
                    uint64_t arg3, uint64_t arg3cage, uint64_t arg4,
                    uint64_t arg4cage, uint64_t arg5, uint64_t arg5cage,
                    uint64_t arg6, uint64_t arg6cage) {

  if (fn_ptr_uint == 0) {
    return -1;
  }

  // Extract the function based on the function pointer that was passed.
  // This is the same address that was passed to the register_handler function.
  int (*fn)(uint64_t) = (int (*)(uint64_t))(uintptr_t)fn_ptr_uint;

  // In this case, we only pass down the cageid as the argument for the geteuid syscall.
  return fn(cageid);
}
```

**Process Coordination:**

Each grate must invoke `execv(argv[1], &argv[1])` exactly once, after registering its syscall handlers.

This design avoids centralized process coordination. Once `execv` is called, further process creation or handler registrations are the responsibility of the executed cage.

This also allows multiple grates to be interposed. For example:

```lind_run geteuid-grate.wasm getuid-grate.wasm example.wasm```


## Compiling a Grate

Grates are compiled similarly to standard Lind programs, with the additional requirement that the WASM module exports the `pass_fptr_to_wt` function.

[`lind_compile`](https://github.com/Lind-Project/lind-wasm/blob/main/scripts/lind_compile) script compiles `.c` programs to `.wasm` binaries for lind.

Example of a compile script: [`examples/geteuid-grate/compile_grate.sh`](./examples/geteuid-grate/compile_grate.sh)

## Running a Grate

Grates are executed like standard Lind programs, that expect cage binaries to be present at `argv[1]`.

Example usage:

```lind_run geteuid-grate.wasm example.wasm```

## Contributing a New Grate

When adding a new grate to `examples/`, follow these rules to keep it easy to discover, build, and test from the repo root.

### Naming

- Use kebab-case for grate names.
- Use `<name>-grate` for C grates.
- Use `<name>-grate-rs` for Rust grates.
- Keep the directory name, build target name, and generated `.cwasm` basename aligned.

Examples:

- `examples/seccomp-grate` -> `seccomp-grate.cwasm`
- `examples/resource-grate-rs` -> `resource-grate-rs.cwasm`

### Recommended Layout

For C grates:

```text
examples/<name>-grate/
├── src/
├── test/
├── build.conf
├── compile_grate.sh
└── README.md
```

For Rust grates:

```text
examples/<name>-grate-rs/
├── src/
├── test/
├── Cargo.toml
└── README.md
```

### Build Conventions

- C grates should provide a `compile_grate.sh` script that is independent of CWD.
- Rust grates should build with `cargo lind_compile`.
- In C grates, make the entry source filename match the grate name, for example `src/seccomp-grate.c`.
- In Rust grates, set `[package].name` in `Cargo.toml` to match the directory name.
- If your grate needs extra runtime files, have the build or test flow copy them explicitly.

### Test Expectations

- Add at least one test program under `test/`.
- Register the grate in [`test/grates_test.toml`](./test/grates_test.toml), refer the documentation on this file for information on naming conventions.
- Prefer focused tests that prove the grate’s syscall interposition behavior instead of broad integration-only coverage.

### Best Practices

- Keep each grate self-contained inside its example directory.
- Document what syscalls are intercepted, what behavior changes, and how to run the grate manually.
- Preserve normal Lind behavior for syscalls you are not intentionally overriding.
- Keep startup and argument handling consistent, since grates are commonly composed with other grates.

### Contributor Checklist

Before sending a new grate for review:

- Create the new directory in `examples/` using the naming rules above.
- Add the build entrypoint (`compile_grate.sh` for C or `Cargo.toml` for Rust).
- Add a README with purpose, build instructions, usage, and test notes.
- Add the grate to [`test/grates_test.toml`](./test/grates_test.toml).
- Verify it builds via `make <grate-name>` or the equivalent direct build command.
- Run `make test GRATE=<grate-name>` before submitting.
