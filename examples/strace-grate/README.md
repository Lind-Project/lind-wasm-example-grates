:Q
## strace-grate

strace-grate is a lightweight utility for tracing system calls. It outputs detailed system call traces along with passed arguments (print paths, associated file descriptors, etc) and their return values.

### strace APIs

strace-grate provides a macro named `DEFINE_HANDLER` that allows user to specify syscalls to be traced (all syscalls are traced by default). It facilitates syscall interposing, logging and forwarding.

Defination:

```
 Arguments:
//      1st:            syscall name
//      2nd:            syscall number
//      3rd - 8th:      ARG type (ARG_INT || ARG_PTR || ARG_STR)
//
// NOTE: if unsure of ARG_TYPE follow:
// https://www.chromium.org/chromium-os/developer-library/reference/linux-constants/syscalls/

DEFINE_HANDLER(syscall_name, syscall_number, ARG_TYPE_1, ..., ARG_TYPE_6)
```

Example:
```
DEFINE_HANDLER(read, 0, ARG_INT, ARG_PTR, ARG_INT)
```

## Building

Uses [lind_compile](https://github.com/Lind-Project/lind-wasm/blob/main/scripts/lind_compile) script with `--compile-grate` flag.

`lind_compile --compile-grate src/strace_grate.c src/strace.c`

or use the `compile_grate.sh` script to build strace grate.

## Implementation

### Interposing

Lind's `threei` subsystem enables syscall interposition. Each syscall is implemented using the `DEFINE_HANDLER` macro, which generates a dedicated handler function for that syscall.

Every handler maintains a log_buffer used to record relevant execution details. When syscalls pass arguments of type string (e.g., pointers to paths or filenames), the handler invokes the `copy_data_between_cages()` helper from threei to safely dereference the value. This allows the system to resolve and log meaningful data such as file paths.

After preprocessing arguments, the handler forwards the syscall to the target cage (i.e., the application running under strace-grate) using `make_threei_call()`. Once the syscall completes, the handler logs the return value and writes the contents of `log_buffer` to `stderr`.

### Syscall Handler Table

All syscall handlers are stored in a centralized syscall handler table `syscall_handler_table`. The `DEFINE_HANDLER` macro not only generates the handler function `<name>_grate` but also defines a corresponding `register_<name>()` function.

This registration function ensures it is executed automatically at grate startup. During this initialization phase, each constructor inserts its associated handler into the table by assigning the function pointer to the appropriate syscall index

## Testing

To validate the implementation, a script is provided that runs Lind's unit test suite under strace-grate. Because strace-grate intercepts and logs all syscalls supported by Lind, this approach ensures comprehensive testing of the interposition layer and verifies that syscall handling behaves correctly across a wide range of scenarios.

## Example Usage:

`lind_run strace_grate.cwasm app.cwasm`

## Future Work

- Flags for tracing user specified system calls.
- Hex to ASCII dump of arguments (e.g flags, modes, etc).
- Add syscall counter and error logging.
