# imfs-grate

Rust implementation of the Lind IMFS grate. It intercepts filesystem syscalls
and serves them from an in-memory filesystem, while still allowing selected host
files to be staged in before execution and selected IMFS files to be dumped back
after execution.

## Build

```bash
cd rust-grates/imfs-grate
cargo lind_compile --output-dir grates
```

The generated grate is typically run as:

```bash
lind_run grates/imfs-grate.cwasm <program> [args...]
```

Add `--log` immediately after the grate to enable IMFS logging:

```bash
lind_run grates/imfs-grate.cwasm --log <program> [args...]
```

Grate options (`--log`, `--preload-file`) may appear in any order; the first
argument that is not one of them starts the program's command line.

## Preloading Host Files

Set `PRELOADS` to a colon-separated list of entries. A bare path is read from
the host and created in IMFS at the same path. An `imfs_path=host_path` entry
(same with the `DUMPS` format) reads `host_path` from the host and creates it
in IMFS at `imfs_path`:

```bash
--env PRELOADS="/hello.c=/home/alice/lind-wasm/lindfs/hello.c"
```

```bash
lind_run \
  --env PRELOADS="/hello.c:/usr/include/stdio.h" \
  grates/imfs-grate.cwasm --log bin/tcc /hello.c -o /hello-3i
```

Use absolute IMFS paths when the program expects absolute paths. For example,
if `tcc` is invoked with `/hello.c`, preload `/hello.c`, not `hello.c`.

Preload details:

- Entries are separated with `:`.
- Empty entries are ignored, as are entries with an empty path on either side
  (`=host_path` and `imfs_path=`). A malformed entry is skipped on its own; the
  entries after it are still staged.
- Non-regular files are skipped.
- Parent directories are created in IMFS as needed. Only the components before
  the final one become directories, so a relative target such as
  `sub/rel.txt=host.txt` still ends up as a file.
- Staging the same IMFS path twice keeps only the last entry's contents; the
  file is truncated before it is rewritten.
- An entry is skipped if its path, or one of its parents, is already taken by
  something that is not a directory (or the final component is a directory).
- Relative IMFS paths resolve against cage 0's cwd (`/`), before any
  application cage exists. IMFS keeps a single node tree, so the child cage
  sees the files at the same paths.
- The Rust implementation reads host files through `make_threei_call`
  (`stat`, `open`, `read`, `close`) instead of `std::fs::read`.

This avoids a Lind/WASM issue where Rust `std::fs::metadata()` can report an
incorrectly huge file size, causing `std::fs::read()` to fail with out-of-memory
even for tiny files.

### How preloading works

Preloading always goes through a *preload archive*: one contiguous block of
memory holding every file to stage, in the format defined by the shared
`lib/preload-archive` crate:

```text
header  magic "LINDPRLD", version u32, entry count u32
entry   path_len u32, mode u32, data_len u64, path bytes, data bytes
```

IMFS is handed that block as a `(pointer, size)` pair (`imfs::preload_from_ptr`)
and builds its nodes straight from the bytes (`src/imfs/preload.rs`):

- IMFS itself never touches the host filesystem tree.
- Files are created directly in the node/chunk arenas, not through the POSIX
  layer, so no fd table, `open()`, or `write()` is involved.
- Each directory prefix is resolved once and cached instead of being walked
  from `/` again for every path component.
- A malformed archive is rejected as a whole before any node is created.

There are two ways to get the archive to IMFS:

1. **`PRELOADS` (one step).** The IMFS grate reads the listed host files into
   an archive itself at startup and then stages it.

2. **`--preload-file <path>` (two steps, prepared ahead of time).** A normal
   native program, [`tools/mkpreload`](../../tools/mkpreload/README.md),
   builds the archive *before* the IMFS grate runs and writes it to a path the
   runtime can see. The IMFS grate then reads that one file into its memory
   and stages from the pointer; nothing else is opened on the host.

   ```bash
   # Step 1, outside Lind: pack the files into one blob. Put it on a
   # memory-backed path under lindfs so it never touches a disk.
   mkpreload lindfs/dev/shm/preload.mem "/hello.c=/home/alice/hello.c:/usr/include/stdio.h"

   # Step 2, whenever you like: run the grate against the blob.
   lind_run grates/imfs-grate.cwasm --preload-file /dev/shm/preload.mem bin/tcc /hello.c -o /hello-3i
   ```

   The path given to `--preload-file` is resolved inside lindfs (the runtime
   chroots there), so `lindfs/dev/shm/preload.mem` on the host is
   `/dev/shm/preload.mem` to the grate. Build the blob once and reuse it for as
   many runs as you like. Every `lind_run` is a separate host process, so a
   file is the only thing that can carry the archive between the two steps;
   a tmpfs path keeps it in memory.

If both are given, the `--preload-file` archive is staged first and `PRELOADS`
entries are layered on top.

## Dumping IMFS Files Back

Set `DUMPS` to a semicolon-separated list. Each entry is either:

```text
imfs_path=host_path
```

or just:

```text
path
```

When `=` is omitted, the same path is used for both IMFS and host.

Dumping happens during grate teardown, after the child cage exits.

```bash
lind_run \
  --env PRELOADS="/hello.c" \
  --env DUMPS="/hello-3i=hello-3i" \
  grates/imfs-grate.cwasm --log bin/tcc /hello.c -o /hello-3i
```

This compiles `/hello.c` inside IMFS and writes the generated `/hello-3i` back
to the host as `hello-3i`.

Dump details:

- Entries are separated with `;`.
- Leading spaces and tabs in each entry are ignored.
- Host parent directories are created before writing the dump target.
- Host-side `mkdir`, `open`, `write`, and `close` are performed through
  `make_threei_call`.

## Common tcc Example

For a small C compile inside IMFS, preload the compiler inputs and dump the
output binary:

```bash
lind_run \
  --env PRELOADS="/usr/lib/i386-linux-gnu/crt1.o:/usr/lib/i386-linux-gnu/crti.o:/usr/include/stdio.h:/usr/lib/i386-linux-gnu/libc.so.6:/usr/lib/i386-linux-gnu/crtn.o:/hello.c" \
  --env DUMPS="/hello-3i=hello-3i" \
  grates/imfs-grate.cwasm --log bin/tcc /hello.c -o /hello-3i
```

If `tcc` reports `undefined symbol 'main'`, first verify that the source file
was preloaded at the same path passed to `tcc`. In practice, `/hello.c` is safer
than `hello.c` because the target program's current working directory may not
match the host shell's current directory.

## Symlink Notes

IMFS supports symlink syscalls, but `PRELOADS` currently stages regular files by
path. If a program expects a dynamic loader or libc at a different path, either
preload the file at the path the program opens or create the required symlink in
the environment before running.

Do not symlink a 64-bit libc into an i386 libc path for 32-bit programs. A
32-bit program needs the i386 libc, for example `libc6:i386` on Debian/Ubuntu.

## Intercepted Syscalls

The Rust IMFS grate registers handlers for common filesystem and lifecycle
syscalls, including:

```text
open, openat, close, read, write, pread, pwrite, readv, writev,
lseek, fcntl, getdents, stat, lstat, fstat, fstatat, statfs, fstatfs,
access, faccessat, mkdir, rmdir, unlink, unlinkat, link, linkat,
rename, renameat, renameat2, symlink, symlinkat, readlink, readlinkat,
chmod, fchmod, fchmodat, chown, lchown, fchownat,
truncate, ftruncate, chdir, fchdir, fsync, fdatasync,
clone, exec
```

Unsupported or intentionally disabled paths return the appropriate negative
errno where possible.

## Tests

```bash
make test GRATE=imfs-grate
```

Two cage binaries run under the grate (`test/preload_test.c` runs twice: once
with `PRELOADS`, once with `--preload-file test/preload_test.mem`, a blob
built by `tools/mkpreload` from the same list, so both paths are checked
against the same expectations):

- `test/imfs_test.c` — the filesystem syscalls themselves.
- `test/preload_test.c` — `PRELOADS` staging. It checks the contents and modes of the files staged from `test/preload_*.txt`, that parent directories are created while the final component stays a file (for absolute and relative targets alike), that re-staging a path truncates it, and that malformed entries are skipped without dropping the entries after them. The `PRELOADS` value is set in `test/grates_test.toml`.

Run tests individually:

```sh
lind_run grates/imfs-grate.cwasm imfs_test.cwasm
lind_run grates/imfs-grate.cwasm preload_test.cwasm
lind_run grates/imfs-grate.cwasm --preload-file preload_test.mem preload_test.cwasm
```

`test/preload_test.mem` is pinned by the `imfs_preload_fixture_matches_this_tool`
unit test in `tools/mkpreload`; after changing the archive format or the fixture
files, regenerate it with:

```sh
cd tools/mkpreload && MKPRELOAD_REGEN_FIXTURE=1 cargo test fixture
```

## Current Limitations

- Preloaded paths are stored in IMFS using the path string provided.
- The preload archive holds every staged file in memory at once (in addition
  to the IMFS chunks that are created from it) until staging finishes, so peak
  memory during preload is roughly twice the total preload size.
- `pipe` and `pipe2` are currently registered as unsupported.
