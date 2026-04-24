# WitnessGrate

`WitnessGrate` is a userspace witness/interposition grate for lind-wasm that signs selected syscalls before forwarding them to the underlying execution path.

The current implementation intercepts:

- `read`
- `write`
- `openat`
- `execve`

For each intercepted syscall, `WitnessGrate`:

1. looks up or creates a per-cage witness context,
2. loads a per-cage Ed25519 seed,
3. derives the cage's keypair,
4. assigns a monotonically increasing sequence number,
5. signs a structured syscall record, and
6. logs the signed evidence before forwarding the syscall through 3i.

## Overview

The design centers around a per-cage witness context:

- `cageid`
- Ed25519 seed / public key / private key
- per-cage sequence number
- lock for serialized signing

Each intercepted syscall is converted into a `syscall_record_t`:

- `seqno`
- `syscallno`
- `cageid`
- 6 syscall arguments
- 6 argument-cage identifiers

That record is signed with Ed25519 and emitted into the witness log.

---

## Supported syscalls

The following syscall numbers are currently handled:

- `SYS_READ = 0`
- `SYS_WRITE = 1`
- `SYS_EXECVE = 59`
- `SYS_OPENAT = 257`

Each one is registered through `register_handler(...)` so that 3i routes matching calls to the corresponding witness handler:

- `read_witness`
- `write_witness`
- `openat_witness`
- `execve_witness`

---

## Execution flow

### 1. Startup

When `WitnessGrate` starts, it:

- initializes logging,
- initializes the in-memory witness context table,
- records its own process ID as the grate ID.

### 2. Parent/child setup

`main()` forks a child that will later `execv()` the target program.

To ensure the child does **not** start executing before the parent has finished registration, the parent and child synchronize through a **shared unnamed semaphore** allocated with:

- `mmap(..., MAP_SHARED | MAP_ANONYMOUS, ...)`
- `sem_init(start_sem, 1, 0)` 

The child blocks on:

```c
sem_wait(start_sem);
```

The parent then:
- creates the witness context for the child cage,
- logs that key material has been prepared,
- registers all syscall handlers for that child cage,
- releases the child with:

### 3. Syscall interception

When a registered syscall is routed to this grate, the corresponding handler calls `signed_forward(...)`.

In `signed_forward(...)`:

- fetches the cage context,
- increments the cage-local seqno,
- builds a syscall_record_t,
- signs it using Ed25519,
- emits the signed record to the witness log,
- forwards the syscall with make_threei_call(...)

## Seed and key management

Each cage gets its own seed and derived keypair.

### Seed lookup order

For cage X, the code first tries `$WITNESS_SEED_DIR/witness.X.seed`. If that file does not exist, it falls back to `./witness.seed`

### Seed format

Each seed file must be exactly 32 bytes long. If the file is missing or has the wrong length, the program aborts.

### Public key emission

When a new cage context is created, the derived public key is logged in hex in a line like:

```txt
PUBKEY cage=<cageid> <hex-public-key>
```

## Log output

The witness log file is controlled by `WITNESS_LOG`. If `WITNESS_LOG` is not set, the default log path is `/tmp/witness.log`

Example log structure:

```txt
=== witness grate start grate_pid=... ===
PUBKEY cage=... <pubkey hex>
=== witness keypair generated for cage ===
SIGNED seq=... syscall=... cage=... a=[...] ac=[...] sig=<signature hex>
=== witness grate finished successfully ===
```

## Build notes

Needs to pull the source code of ed25519 from app repo, and set corresponding path to compilation scripts.

## Running

```sh
./witness_grate <target_program> [target args...]
```
