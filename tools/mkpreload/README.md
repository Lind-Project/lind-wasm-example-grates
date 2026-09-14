# mkpreload

A plain native program (no Lind involved) that packs host files into an IMFS
*preload archive*: one contiguous blob in the format defined by
`lib/preload-archive`. It is the "prepare the memory first" half of preloading;
the IMFS grate's `--preload-file` option is the other half.

```text
mkpreload [--mode OCTAL] <out> <entry>...
```

- `<out>` is where the archive is written. Point it at a memory-backed
  directory that the Lind runtime can see, such as a tmpfs mounted at
  `lindfs/dev/shm`, and the blob lives in RAM only.
- Each `<entry>` is `imfs_path=host_path` or a bare path used on both sides,
  exactly like the IMFS grate's `PRELOADS`. An entry may itself be a
  colon-separated list, so `mkpreload out "$PRELOADS"` works as-is.
- `--mode` sets the permission bits of every packed file (default `777`, the
  same as `PRELOADS`).

Non-regular and unreadable files are reported and skipped; the rest are still
packed. Staging the same IMFS path twice keeps the last entry, as `PRELOADS`
does. Exit status is non-zero if nothing could be packed or the output cannot
be written.

## Build

```bash
cd tools/mkpreload
cargo build --release      # -> target/release/mkpreload
```

## Example

```bash
# 1. Pack, outside Lind. lindfs/dev/shm is /dev/shm inside the runtime's chroot.
tools/mkpreload/target/release/mkpreload \
  lindfs/dev/shm/tcc.mem \
  "/hello.c=/home/alice/hello.c:/usr/include/stdio.h:/usr/lib/i386-linux-gnu/crt1.o"

# 2. Run the IMFS grate against the blob, as many times as you like.
lind_run grates/imfs-grate.cwasm --preload-file /dev/shm/tcc.mem bin/tcc /hello.c -o /hello-3i
```

The grate reads the blob into its own memory with a single open/read/close and
builds its filesystem from that pointer. Each `lind_run` is a separate host
process, so a path under lindfs is the only channel that can carry the archive
from step 1 to step 2; a tmpfs path keeps it off the disk.

## Tests

`cargo test` covers argument parsing and packing, and pins
`rust-grates/imfs-grate/test/preload_test.mem`, the blob the IMFS grate's
`preload_test.c` loads in the test suite. Regenerate that fixture after
changing the format or the fixture files:

```bash
MKPRELOAD_REGEN_FIXTURE=1 cargo test fixture
```
