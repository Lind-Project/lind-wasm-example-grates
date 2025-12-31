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
├── tests/              // Tests for this grate.
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

```lind_run geteuid_grate.wasm getuid_grate.wasm example.wasm```


## Compiling a Grate

Grates are compiled similarly to standard Lind programs, with the additional requirement that the WASM module exports the `pass_fptr_to_wt` function.

[`lind_compile`](https://github.com/Lind-Project/lind-wasm/blob/main/scripts/lind_compile) script compiles `.c` programs to `.wasm` binaries for lind.

Example of a compile script: [`examples/geteuid-grate/compile_grate.sh`](./examples/geteuid-grate/compile_grate.sh)

## Running a Grate

Grates are executed like standard Lind programs, that expect cage binaries to be present at `argv[1]`.

Example usage:

```lind_run geteuid_grate.wasm example.wasm```

