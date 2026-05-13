# net-routing-clamp

A meta-grate that routes network syscalls to clamped child grates based on port range. Sockets that bind or connect to ports in the range get routed through the child grate stack. All other network traffic passes through to the kernel.

## Usage

```bash
net-routing-clamp --ports <low>-<high> %{ <grate1> [grate2 ...] %} <program> [args...]
```

### Examples

Route ports 8080-8090 through an mTLS grate:
```bash
lind-wasm grates/net-routing-clamp.cwasm --ports 8080-8090 %{ grates/mtls-grate.cwasm %} server.cwasm
```

Route a single port through a rate-limiting grate:
```bash
lind-wasm grates/net-routing-clamp.cwasm --ports 443-443 %{ grates/resource-grate.cwasm resource.cfg %} server.cwasm
```

Stack multiple ranges using recursion:
```bash
lind-wasm grates/net-routing-clamp.cwasm --ports 80-89 %{ \
  grates/net-routing-clamp.cwasm --ports 443-443 %{ grates/mtls-grate.cwasm %} \
  http-server.cwasm \
%}
```

## How it works

1. **Startup**: Parses `--ports` and the `%{ ... %}` block. Forks a child cage and registers lifecycle handlers (register_handler, exec, fork, exit) on it.

2. **Clamp phase**: The child cage execs the first grate in the `%{` block. Any `register_handler` calls from that grate are intercepted — the net-routing-clamp allocates alt syscall numbers and builds a routing table. When `%}` is reached, the clamp phase ends and the real program execs.

3. **Runtime routing**: For each intercepted syscall:
   - **bind/connect**: Reads the sockaddr, extracts the port. If the port is in range, marks the fd as clamped (via fdtables `perfdinfo=1`) and routes to the child grate's handler.
   - **accept**: If the listening socket is clamped, the accepted fd inherits that status.
   - **sendto**: Checks both the fd and the destination addr port.
   - **read/write/sendmsg/recvmsg/etc.**: Routes based on whether the fd is clamped.
   - **close/dup/dup2**: Maintains fd tracking and clamped status inheritance.

## Intercepted syscalls

| Category | Syscalls |
|----------|----------|
| Socket lifecycle | socket, bind, connect, listen, accept, shutdown |
| I/O | read, write, readv, writev, sendto, recvfrom, sendmsg, recvmsg |
| FD management | close, dup, dup2 |
| Process lifecycle | fork, exec, exit, register_handler |

## Building

```bash
cd rust-grates/net-routing-clamp
cargo lind_compile --output-dir grates
```

## Testing

```bash
# Compile the test
lind-clang -s test/net_routing_test.c

# Run with testing-grate as the clamped grate (stubs bind/connect/etc.)
lind-wasm grates/net-routing-clamp.cwasm \
  --ports 8080-8090 \
  %{ grates/testing-grate.cwasm -s 49:0,42:0,43:0 %} \
  net_routing_test.cwasm
```

The testing-grate stubs:
- `49` (bind) → returns 0
- `42` (connect) → returns 0
- `43` (accept) → returns 0
