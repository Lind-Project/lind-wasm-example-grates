# resource-grate

A Rust grate that enforces per-sandbox resource limits using the same
token-bucket algorithm as repy's `nanny.py`. Limits are shared across all
child cages in the sandbox.

## Resource types

| Type | Enforcement | Examples |
|------|------------|----------|
| **Renewable** | Token-bucket rate limiter (bytes/sec). Callers are blocked when consumption exceeds the per-second budget. | `filewrite`, `fileread`, `netsend`, `netrecv`, `loopsend`, `looprecv`, `lograte`, `random` |
| **Fungible** | Hard cap on concurrent count. Requests beyond the limit are denied immediately. | `filesopened`, `events` (threads), `insockets`, `outsockets` |
| **Individual** | Port allowlists. Bind/connect/sendto to unlisted ports returns `EACCES`. | `connport`, `messport` |

## Intercepted syscalls

- **File I/O**: `open`, `close`, `read`, `write`, `pread64`, `pwrite64`, `readv`, `writev`
- **Network**: `socket`, `bind`, `listen`, `accept`, `connect`, `sendto`, `recvfrom`, `sendmsg`, `recvmsg`
- **Threading**: `clone`, `exit`
- **Random**: `getrandom`

Writes to fd 1 (stdout) and fd 2 (stderr) are charged against `lograte`
instead of `filewrite`.

## Config format

Repy-style, one resource per line:

```
resource <name> <value>    # comment
```

Example (`test/test_resources.cfg`):

```
resource filewrite 50000        # 50 KB/sec
resource fileread 50000
resource lograte 30000          # 30 KB/sec
resource random 10000           # 10 KB/sec
resource filesopened 5          # max 5 open files
resource events 10              # max 10 threads
resource connport 12345         # allowed port
resource messport 12345
```

## Usage

```bash
lind-wasm grates/resource-grate.cwasm <config_file> <cage_binary> [args...]
```

Or via environment variable:

```bash
RESOURCE_CONFIG=<config_file> lind-wasm grates/resource-grate.cwasm <cage_binary> [args...]
```

## Building

```bash
cd examples/resource-grate
cargo lind_compile --output-dir grates
```

## Testing

```bash
# Compile and run against the test config
lind-wasm grates/resource-grate.cwasm test_resources.cfg resource_test.cwasm
```

The test suite (`test/resource_test.c`) includes:

- **Correctness tests**: write/read round-trips, data integrity checks, zero-byte edge cases
- **Fungible cap tests**: filesopened limit, close-and-reopen cycling, rapid open/close at cap
- **Timed rate-limit tests**: bulk write/read/pwrite/writev/readv/getrandom/lograte operations that verify throttling by measuring elapsed time against the configured rate
- **Network tests**: socket creation, bind on allowed/disallowed ports
- **Simultaneous resource tests**: concurrent file and stdout writes hitting independent rate limits
