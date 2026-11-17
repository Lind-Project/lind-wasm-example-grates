# seeded-random-grate

Answers every `getrandom` of its child cages from a declared seed, so the
bytes a program reads depend only on the seed, on the cage that asks and on
how much that cage has read before, never on the hardware or the host.

Lind's glibc takes `arc4random` and the names of `mktemp` and `tmpnam` from
`getrandom`, so the grate covers these too.

## How it works

1. The seed comes from `RANDOM_GRATE_SEED`, an unsigned 64-bit number. Without
   it the seed is 0. A value that does not parse stops the grate.
2. Each cage has its own stream: ChaCha20 with the seed in the key and the
   cage id as the nonce. A call returns the next bytes of the calling cage's
   stream.
3. A forked cage has a new cage id, so it starts a new stream and never
   repeats its parent's bytes. `exec` keeps the cage id, so the new program
   continues the stream.
4. All flags get the same stream. The flag combinations Linux refuses return
   `EINVAL`. One call returns at most 32 MiB - 1 bytes, as in Linux.
5. Forked children inherit the handler, so a whole build reads from one seed.

A cage's bytes are the same on every run while the cage has the same id and
reads in the same order, as in a sequential build. Parallel jobs can get their
cage ids in a different order on each run, and the threads of one cage can
read in a different order.

## What it does not cover

- `random_get`, the import the runtime answers itself (WASI programs and Rust's
  `HashMap` seeds use it). It does not pass through 3i.
- `/dev/urandom` and `/dev/random`. These are files, so they belong to the
  grate that serves the file system.
- `mkstemp`. Its first name comes from the clock, not from `getrandom`.
- The grates and the runtime below this grate.

The bytes are not secret: anyone who knows the seed can compute them. Do not
run a program that makes keys under this grate.

## Usage

Run it outside the programs whose randomness it should fix:

```bash
lind_run --env RANDOM_GRATE_SEED=42 \
  grates/seeded-random-grate.cwasm make ...
```

When the child exits, the grate prints how many calls and bytes it served.

## Test

`test/random_test.c` computes the streams itself and compares them with what
`getrandom` returns: successive reads, a read longer than a block, the
refused flags, and a forked child. It also prints the bytes it read, so two
runs can be compared line by line.

```bash
make test GRATE=seeded-random-grate
```

## Build

```bash
make rust/seeded-random-grate
```
