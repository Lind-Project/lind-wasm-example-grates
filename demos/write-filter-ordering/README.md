# Write Filter Ordering Demo

Demonstrates how grate composition order changes observable behavior.
Two independently-written grates — strace-grate and write-filter-grate —
are composed in both orders without modification.

## Ordering A: strace above write-filter

```
strace-grate → write-filter-grate → cage
```

Strace sees ALL attempted writes, including those subsequently denied by
the write filter. A write to `data.db` appears in the trace log with its
return value of -EPERM.

## Ordering B: write-filter above strace

```
write-filter-grate → strace-grate → cage
```

The write filter denies the `data.db` write before it reaches strace.
Strace only sees writes that pass the filter. The denied write is
invisible to it.

## What it tests

1. write to `output.log` — succeeds (allowed by filter)
2. write to `data.db` — denied with EPERM
3. pwrite to `data.db` — also denied
4. write to `another.log` — succeeds
5. read from `data.db` — not blocked (only writes are filtered)

## Running

```bash
bash demos/write-filter-ordering/build.sh
bash demos/write-filter-ordering/run.sh
```
