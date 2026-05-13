# mTLS Propagation Demo

Demonstrates that mTLS enforcement propagates automatically to all
dynamically spawned worker cages via handler table inheritance.

The mtls-grate intercepts `connect()` and `accept()` at the syscall
boundary and wraps the underlying fd in a TLS session. Because handler
tables are inherited across `fork`, every worker cage gets mTLS without
any per-worker configuration. No worker can bypass it.

## What it tests

1. **Depth 0**: Main process accepts a connection, exchanges data through mTLS
2. **Depth 1**: Forked worker accepts its own connection — mTLS inherited
3. **Depth 2**: Worker spawns another worker — mTLS still active

Each depth runs an independent server+client test on a different port.
The cage code does plain TCP — the grate handles all TLS transparently.

## Running

```bash
bash demos/mtls-propagation/build.sh
bash demos/mtls-propagation/run.sh
```

## Why existing tools can't do this

`LD_PRELOAD` cannot replicate this: statically linked binaries and child
processes that clear `LD_PRELOAD` before `exec` bypass the shim entirely.
Grate handler tables are inherited at the cage level, not through the
environment, so they cannot be cleared or bypassed.
