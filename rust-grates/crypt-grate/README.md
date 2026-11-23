# crypt-grate

Transparent file encryption for Lind cages. FUSE style encrypted
filesystems similar to gocryptfs. The cage reads and writes plaintext with
ordinary syscalls, the files on disk contain only ciphertext. The cage never
sees the key.

crypt-grate runs inside [fs-routing-clamp](../fs-routing-clamp), so that only
one directory tree is encrypted and everything else (including the cage's
stdin/stdout) is untouched.

## Usage

```bash
# A key: 32 random bytes, as raw bytes or 64 hex digits.
openssl rand -hex 32 > lindfs/keys/secure.key

lind-wasm grates/fs-routing-clamp.cwasm --prefix /secure %{ \
    grates/crypt-grate.cwasm --key-file /keys/secure.key \
%} app.cwasm
```

Every regular file the app (or any process it forks) creates or opens under
`/secure` is stored encrypted. Files must be created through the grate: a
plaintext file placed under the prefix by other means fails to read with `EIO`
(it is never misread as data). Keep the key file outside the prefix and
outside anything the cage can read.

Options come before the command: `--key-file <path>` (or `--key-file=<path>`)
is required; `-h` / `--help` prints usage. The first other argument starts the
command to exec, which under fs-routing-clamp is `%}`.

Run without fs-routing-clamp, the grate treats *every* regular file the
program touches as encrypted, including stdout redirected to a file. It prints
a warning when it is started that way.

## On-disk format

```text
header   "LCRY" | version u16 = 1 | reserved u16 | file id (16 random bytes)
block 0  nonce (12) | AES-256-GCM ciphertext of up to 4096 bytes | tag (16)
block 1  ...
```

- A file is either empty (0 bytes) or a header followed by blocks. Every block
  but the last holds 4096 plaintext bytes, so any plaintext offset maps to a
  fixed position on disk: random-access reads and writes only touch the blocks
  involved. A partial-block write decrypts, merges, and re-encrypts that block.
- Each block is sealed with a fresh random nonce and authenticated together
  with the file id and its block number. Modified, reordered, or
  cross-file-swapped blocks fail with `EIO` instead of returning wrong data.
  Like gocryptfs, this does not detect whole blocks being cut off the end of a
  file, or a block being rolled back to an older version of itself.
- The content key is derived from the key file with HKDF-SHA256; the key file
  itself is never used directly for encryption.
- Overhead: 24 bytes per file plus 28 bytes per 4 KiB block (about 0.7%).

File names, sizes (rounded to blocks), and timestamps are not hidden.

## Intercepted syscalls

| Syscall | Behavior for regular files |
|---|---|
| `open`, `openat` | Opened read-write underneath (partial-block writes must read first) and without `O_APPEND` (see below). |
| `read`, `write`, `pread`, `pwrite`, `readv`, `writev`, `preadv`, `pwritev` | Decrypt / encrypt through the block layer. |
| `lseek` | Positions in plaintext; `SEEK_END` uses the plaintext size. |
| `fstat`, `stat`, `lstat`, `newfstatat` | Report the plaintext size. |
| `ftruncate`, `truncate` | Shrink (re-sealing the new last block) or grow with zeros. |
| `fcntl` | `F_GETFL` / `F_SETFL` translate the `O_APPEND` marker; everything else is forwarded. |
| `mmap` | File-backed mappings of encrypted files fail with `ENODEV`. |

Directories, FIFOs, sockets and devices are forwarded unchanged.

## How it keeps state

Inside fs-routing-clamp a clamped grate never sees `fork`, `exec` or `exit`,
so crypt-grate keeps **no per-descriptor state**:

- **File offset.** The grate does only positioned I/O on the ciphertext, so
  the kernel's own file offset is free to hold the *plaintext* offset. The
  kernel already shares it correctly across `dup` and `fork`.
- **`O_APPEND`.** Linux makes `pwrite` on an `O_APPEND` descriptor ignore its
  offset, so the real flag must be removed. `O_NONBLOCK` has no effect on
  regular files, so the grate stores append mode there; `fcntl` reports it back
  as `O_APPEND`.
- **Header and sizes** are read from the file on every call, so any number of
  descriptors and processes see the same file.

A single lock serializes encrypted I/O inside the grate, so concurrent partial
writes to the same block from different descriptors or processes cannot lose
updates. The lock is never held while forwarding a call that could block.

## Code layout

The encryption core is a library with no Lind dependencies; the grate is a
thin binary on top of it.

| File | Contents |
|---|---|
| `src/format.rs` | Header encoding, block layout, plaintext ↔ ciphertext size mapping. |
| `src/cipher.rs` | Key-file parsing, HKDF key derivation, sealing and opening blocks. |
| `src/cryptfile.rs` | `CryptFile`: plaintext `read_at` / `write_at` / `set_len` over any `BlockIo` (positioned I/O + size + truncate). |
| `src/sys.rs` | 3i plumbing: `make_threei_call` wrapper, cage ↔ grate copies, `CageFd` (a `BlockIo` over a cage fd), `getrandom`. |
| `src/handlers.rs` | The syscall handlers listed above. |
| `src/main.rs` | Argument parsing, key loading, handler registration. |

## Building

```bash
cd rust-grates/crypt-grate
cargo lind_compile --release --output-dir grates
```

## Testing

The test runs inside Lind under fs-routing-clamp, so build the clamp too:

```bash
make rust/fs-routing-clamp
make test GRATE=crypt-grate
```
