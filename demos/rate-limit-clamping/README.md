# Rate-Limit Clamping Demo

Demonstrates scoping a rate limit to a specific port using grate composition.
The resource-grate enforces a bytes-per-second budget, and the
net-namespace-grate routes only port 5432 traffic through it. Local file
I/O is unaffected.

No existing mechanism can scope a rate limit this precisely within a single
process. The resource-grate was written with no knowledge of
net-namespace-grate — neither required modification to enable the composition.

## Composition

```
net-namespace-grate --ports 5432-5432
  -> resource-grate (50 KB/s netsend limit)
Host kernel (everything outside port 5432)
```

## What it tests

1. **File writes**: 200KB written at full speed (~instant)
2. **Socket writes to port 5432**: 200KB throttled to 50 KB/s (~4 seconds)

The difference in throughput proves that the rate limit is scoped to the
clamped port range and does not affect other I/O.

## Running

```bash
bash demos/rate-limit-clamping/build.sh
bash demos/rate-limit-clamping/run.sh
```
