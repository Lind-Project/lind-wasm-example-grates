# Example Grates for Lind

This reposistory contains a collection of example grate implementations that can be used with the [Lind runtime](https://github.com/Lind-Project/lind-wasm)

Grates provide custom syscall wrappers for Lind cages. Each example grate here demonstrates how to override one or more syscalls with a custom implementation.

For more details on Lind and grates, refer to the official [documentation.](https://lind-project.github.io/lind-wasm/)

## Repository Structure 

Each directory under `examples/` contains a standalone grate implementation.

For a grate written in `C`, the typical structure for an individual grate is:

```
examples/<name>-grate
├── src/                // .c and .h source files.
├── tests/              // Tests for this grate, run as child cages.
├── build.conf          // Configuration file to describe additional build flags, `--max-memory` for wasm, and entry point for the grate.
├── compile_grate.sh    // Compilation script that places the final *.wasm files in the `output/` folder.
└── README.md 
```

## Writing a Grate

By default, syscalls called by a grate are redirected to `rawposix`. With grates, specific specific syscalls from a child cage can be redirected to custom handlers defined in the grate. 

Following the example in `examples/geteuid-grate`:

**Registering Syscalls:**

First, define a custom implementation of the syscall.

```c
int geteuid_grate(uint64_t cageid) {
    return 10;
}
```

Next, register this function as the handler for `geteuid` using the `register_handler` function

```c
pid_t pid = fork();
if (pid == 0) {
    int cageid = getpid();

    uint64_t fn_ptr_addr = (uint64_t)(uintptr_t_) &geteuid_grate;
    register_handler(cageid, 107, 1, grateid, fn_ptr_addr);

    // Typically, the cage executable is provided as argv[1]
    execv(argv[1], &argv[1]);
}
```

**Dispatch Handling:**

Each grate must define a dispatcher function named `pass_fptr_to_wt` which serves as the entry point for all interecepted syscalls in that grate. 

The dispatcher is invoked using:
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

## Compiling a Grate

Grates are compiled similarly to regular Lind programs, with the additional requirement that the `pass_fptr_to_wt` function must be an export of the WASM module.

Example of a compile script: [`examples/geteuid-grate/compile_grate.sh`](./examples/geteuid-grate/compile_grate.sh)

## Running a Grate

Grates are run like regular lind programs, using the `lind_run` script. 

By convention, a grate expects the child cage's command-line arguments to begin at `argv[1]`. The grate must execute the child cage using `execv(argv[1], &argv[1]`, thereby forwarding all remaining arguments to the cage unchanged.

Example usage:

`lind_run geteuid_grate.wasm geteuid.wasm`
