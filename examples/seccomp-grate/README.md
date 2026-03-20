## seccomp-grate

seccomp-grate is a high-performance system call filtering layer that utilizes a dynamic runtime configuration file to enforce security policies, securely blocking unauthorized actions.

seccomp-grate enables filtering of incoming system calls. It allow users to define a config file with whitelist or blacklist system calls

## Implementation

### Configuration Parsing

At startup, the grate process parses an INI configuration file to map system call numbers. It populates a global state array `syscall_mode`, marking each call as either Whitelist (WL) or Blacklist (BL), and applies a configurable `[default]` policy to any unlisted calls.

### Handler Registration

seccomp-grate performs selective registration. It iterates through the state array and only registers blacklisted syscalls. Whitelisted syscalls execute natively, eliminating the context-switching overhead of trapping to the grate.

### Interception

If the cage attempts a blacklisted syscall, grate traps the operation and routes it to the `blacklist_handler()`. This handler immediately returns -EPERM (Operation not permitted) to securely block the unauthorized action.

## Policy Configuration:

The seccomp-grate uses a standard INI configuration file to define its security boundaries. The parser evaluates this file at startup to build the interception rules before the target binary is allowed to execute.

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
# seccomp-grate configuration

[default]
# Fallback policy: block any syscall not explicitly listed below
blacklist

[whitelist]
# Allowed: basic file and process operations
SYS_read
SYS_write
SYS_open
SYS_openat
SYS_close
SYS_exit
SYS_exit_group

[blacklist]
# Can still explicitly list blocked calls for clarity or documentation
SYS_mkdir
SYS_rmdir
SYS_socket
SYS_exec
```

### NOTE

* If the [default] section is omitted, seccomp-grate automatically blacklists all unlisted system calls as a safety fallback.

## Building

Uses [lind_compile](https://github.com/Lind-Project/lind-wasm/blob/main/scripts/lind_compile) script with `--compile-grate` flag.

`lind_compile --compile-grate src/seccomp_grate.c src/seccomp.c`

or use the `compile_grate.sh` script to build seccomp grate. Compile script copies `src/seccomp-config.ini` file to `lindfs/`.

## Testing

To verify the grate functioning, you can use the provided `tests/seccomp_mkdir_test.c` test alongside `src/seccomp-config.ini`. This configuration sets an "Allow by Default" policy. It explicitly blocks `SYS_rmdir` while allowing `SYS_mkdir` to pass:

```
[default]
whitelist

[whitelist]
SYS_mkdir

[blacklist]
SYS_rmdir
```

## Example Usage:

`lind_run seccomp_grate.cwasm seccomp-config.ini app.cwasm`

## Future Work

- Constraint policy defining.
