# logical-clock-grate

Answers every `clock_gettime` of its child cages from a declared epoch plus a
logical tick, so the time a program reads depends only on the order of its
reads, never on the host clock.

Lind's glibc implements `time` and `gettimeofday` with `clock_gettime`, so the
grate covers all three.

## How it works

1. The epoch comes from `LOGICAL_CLOCK_EPOCH`, in seconds. Without it the
   epoch is 0.
2. Every call advances the clock by 1 ms and returns the new value, so loops
   that wait for time to pass still end.
3. All clock ids get the same answer.
4. Forked children inherit the handler, so a whole build sees one clock.

The clock is deterministic only while the reads happen in a fixed order, as in
a sequential build. Parallel jobs can read it in a different order on each run.

## Usage

Run it outside the grates and programs whose time it should fix:

```bash
lind_run --env LOGICAL_CLOCK_EPOCH=1700000000 \
  grates/logical-clock-grate.cwasm grates/imfs-grate.cwasm make ...
```

Give the IMFS grate the same `LOGICAL_CLOCK_EPOCH`, so that file times start
from the same epoch. Some tools, binutils `ar` among them, treat a file time
of zero as unknown and use the current time instead.

## Example

GNU `ar` in its non-deterministic mode, `ar rcU`, writes two times into an
archive: each member's file time, and the time `ar` ran into the symbol table.
`SOURCE_DATE_EPOCH` fixes the first but not the second. Under this grate and
the IMFS grate with the same epoch, both are the declared epoch, and repeated
builds produce the same archive.

## Build

```bash
make rust/logical-clock-grate
```
