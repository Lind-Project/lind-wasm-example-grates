## seccomp-grate

seccomp-grate is a high-performance system call filtering layer that utilizes a dynamic runtime configuration file to enforce security policies, securely blocking unauthorized actions.

seccomp-grate enables filtering of incoming system calls. It allow users to define a config file with whitelist or blacklist system calls

## Implementation

### Configuration Parsing

At startup, the grate parses and validates provided configuration file. It builds a global state array `syscall_mode` that maps every system call to a Whitelist (WL) or Blacklist (BL) state, applying defined [default] rule to any operations not explicitly listed.

### Handler Registration

seccomp-grate performs selective registration. It iterates through the state array and only registers blacklisted syscalls. Whitelisted syscalls execute natively, eliminating the context-switching overhead of trapping to the grate.

### Interception

If the cage attempts a blacklisted syscall, grate traps the operation and routes it to the `blacklist_handler()`. This handler immediately returns -EPERM (Operation not permitted) to securely block the unauthorized action.

## Policy Configuration:

The seccomp-grate uses a configuration file to define its security boundaries. The parser evaluates this file at startup to build the interception rules before the target binary is allowed to execute.

### Sections

* `[whitelist]`: Syscalls listed here are explicitly allowed. They bypass the interception layer entirely and execute natively with zero overhead.
* `[blacklist]`: Syscalls listed here are explicitly blocked. They are trapped, routed to the `blacklist_handler`, and immediately return `-EPERM`.
* `[default]`: Defines the overarching fallback policy for any syscall not explicitly listed in the file. It accepts a single value of either `whitelist` or `blacklist`.

### Syntax Rules

* System calls must be listed one per line using their standard `SYS_` prefix (e.g., SYS_read). Supported syscalls are listed (here)[https://github.com/Lind-Project/lind-wasm/blob/main/src/rawposix/src/syscall_table.rs].
* Empty lines and comments (lines beginning with # or ;) are ignored by the parser.

### Example Configuration

* This example demonstrates a "Deny by Default" security posture, where only explicitly approved system calls are permitted to execute:

```
; seccomp-grate configuration

; Fallback policy: block any syscall not explicitly listed below
[default]
blacklist


; Allowed: basic file and process operations
[whitelist]

SYS_futex
SYS_exec
SYS_mmap
SYS_munmap
SYS_exit
SYS_exit_group

SYS_read
SYS_write
SYS_open
SYS_close


; Can explicitly list blacklisted calls for clarity or documentation.
[blacklist]
SYS_mkdir
SYS_rmdir
SYS_socket
```

### NOTE

* If the [default] section is omitted, seccomp-grate automatically blacklists all unlisted system calls as a safety fallback.

## Building

Uses [lind_compile](https://github.com/Lind-Project/lind-wasm/blob/main/scripts/lind_compile) script with `--compile-grate` flag.

`lind_compile --compile-grate src/seccomp_grate.c src/seccomp.c`

or use the `compile_grate.sh` script to build seccomp grate. Compile script copies `src/seccomp-config.ini` file to `lindfs/`.

## Example Usage:

`lind_run seccomp_grate.cwasm <seccomp_configuration> <app.cwasm> ...`

## Testing

To verify the grate's functionality, you can execute the provided `tests/seccomp_chmod_test.c` test along side `src/policies/seccomp_blacklist_test.conf` and `seccomp_whitelist_test.conf`. These configuration files demonstrates example of both "Allow by Default" and "Deny by Default" policies.

### Example Policies:

* `seccomp_blacklist_generic.conf`: Enforces a strict "Deny by Default" policy. It includes a baseline [whitelist] of mandatory system calls required for the cage to successfully initialize and terminate. It is highly recommended to use this file as a skeleton when building your own blacklist configurations.
* `seccomp_whitelist_test.conf`: An "Allow by Default" profile. It permits all system calls natively, selectively blacklisting only the operations necessary to trigger the test's security assertions.
* `seccomp_blacklist_test.conf`: A "Deny by Default" profile. It strictly blocks all system calls, providing an explicit whitelist of only the bare minimum operations required for the test to run and exit cleanly.

**NOTE**: If you set [default] to blacklist, there are several core system calls that must be explicitly whitelisted for the environment to function. Always use the `seccomp_blacklist_generic.conf` file as your starting point to avoid immediate execution failures.

### Executing Test:

- `lind_run seccomp_grate.cwasm seccomp_whitelist_test.conf seccomp_chmod_test.c`
- `lind_run seccomp_grate.cwasm seccomp_blacklist_test.conf seccomp_chmod_test.c`

## Future Work

- Constraint based policy defining.
