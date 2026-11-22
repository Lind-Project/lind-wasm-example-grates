# user-view-grate

Gives each user their own view of a file. A policy names the files to protect and, for every
user, which lines of a file they see, how those lines are rewritten before they see them, and
whether what they write goes back into the real file.

Two things this makes possible without any privileged code in the system:

- **A password database without setuid.** Every user opens `/etc/shadow` and finds a one-line
  file: their own entry. They can rewrite it, and only it. Nothing runs as root.
- **Redaction on read.** One log on disk; support staff read it with card numbers masked, an
  auditor reads it raw, and a customer's process reads only the lines about that customer.
  Nobody keeps a second, sanitized copy in sync.

```bash
lind-wasm grates/user-view-grate.cwasm --policy views.conf [--user NAME] [--tmpdir DIR] [--] program [args...]
```

| Option | Meaning |
|---|---|
| `--policy FILE` | The policy file (required). |
| `--user NAME` | Treat every cage under this grate as `NAME`. Without it a cage is identified by its effective uid. |
| `--tmpdir DIR` | Where view files are created. Default `/tmp`. Created if it does not exist. Must be the same directory for the grate and its cages. |

## Policy

```
# uid -> name, used when cages are identified by uid
[users]
0    = root
1000 = alice

[file /etc/shadow]
user root
  raw
user *
  keep ^{user}:
  write

[file /var/log/payments.log]
user auditor
  raw
user support, oncall
  drop \bDEBUG\b
  replace \b(\d{4})-\d{4}-\d{4}-(\d{4})\b => $1-****-****-$2
user *
  keep \buser={user}\b
  replace card=\S+ => card=[redacted]
```

Each `[file PATH]` section protects one file. Under it, a `user` line names users (names, uids,
or `*`) and the lines after it say what they get. The first block that names the calling user
applies. **A user that no block names is denied**, and a file with no section is not touched.

| Directive | Meaning |
|---|---|
| `raw` | The real file, as if the grate were not there. |
| `deny` | `open` fails with `EACCES`. |
| `keep REGEX` | Show only lines that match. Several `keep` lines are alternatives. |
| `drop REGEX` | Hide lines that match, even if a `keep` matched. |
| `replace REGEX => TEXT` | Rewrite each shown line. `$1`, `${name}` refer to groups; an empty `TEXT` deletes the match. Applied in the order written. |
| `write` | What the user writes replaces their lines in the real file. Not allowed together with `replace`. |
| `readonly` | Every line, no writing. For a block that needs no other directive. |

`{user}` and `{uid}` in a pattern or replacement stand for the calling user's name and uid. The
name is inserted as literal text. Patterns use the [regex](https://docs.rs/regex) syntax and
match bytes, one line at a time, without its newline.

## How it works

**Matching a file, not a path.** A call is matched by the file it reaches (device and inode),
not by the spelling of its path. A symlink, a hard link, a relative path or `..` lead to the
same view. The grate looks up what each rule's path names on every call that could reach it and
keeps protecting files the path named before, so rotating a log or moving its directory does
not open a way around a rule.

**Opening.** When a user with a view opens a protected file, the grate reads the real file,
renders the view into a new file in `--tmpdir`, opens that file for the cage with the flags the
cage asked for, and unlinks it. The cage holds an ordinary descriptor on a file that contains
only what the user may see, so `read`, `pread`, `lseek`, `fstat`, `mmap` and `sendfile` behave
exactly as on any file and are not intercepted. The real file is never open in the cage.

**Writing.** Descriptors on a writable view are tracked through `dup`, `fcntl`, `fork` and
`exec`. The view is merged into the real file when one of them is closed or synced, and when a
cage holding one execs or exits:

1. Every line the user wrote must be one they could see. With `keep ^{user}:`, alice can write
   only lines starting `alice:`. Otherwise nothing is written and `close` (or `fsync`) fails
   with `EPERM`.
2. The real file is read again, and the lines the user can see in it are replaced, in place and
   in order, by the lines they wrote. Extra lines go after their last line (or at the end of
   the file); lines they removed are removed. Lines they cannot see are never touched.

A user without `raw` cannot `truncate`, `unlink` or `rename` a protected file, or rename
another file over it (`EACCES`).

## Intercepted syscalls

| Category | Syscalls |
|---|---|
| Opening | open, openat |
| Merging edits | close, fsync, fdatasync |
| Descriptor tracking | dup, dup2, dup3, fcntl, clone, execve, exit, exit_group |
| Protecting the file | truncate, unlink, unlinkat, rename, renameat, renameat2 |

With nothing in the policy, every call is forwarded untouched. Otherwise an `open` costs one
`stat` per rule plus a `stat` and an `fstat`; reads and writes cost nothing extra. Put the
grate under `fs-routing-clamp` to pay that only for the directories that hold protected files:

```bash
lind-wasm grates/fs-routing-clamp.cwasm --prefix /etc %{ \
  grates/user-view-grate.cwasm --policy views.conf \
%} program
```

## Limits

- A view is a snapshot taken at `open`. Lines appended to the real file later do not appear in
  a descriptor that is already open, so `tail -f` on a view shows nothing new.
- Files up to 8 MiB are served; a larger one fails with `EFBIG`. (A grate has 64 MiB of memory,
  and a view is rendered in it.)
- The real file is rewritten in place, under `flock`. A raw reader can see it half-written for a
  moment, and a crash mid-write can leave it so.
- `stat` on a protected path reports the real file's size and times.
- A program that updates a file by writing a new one and renaming it over the old (as `passwd`
  does) is refused the rename. It has to write the file in place.
- A user without `raw` cannot remove a hard link to a protected file either: the link is the
  file.
- A path is checked before the open and the descriptor after it. A cage that swaps the path in
  between, from a second thread, can hold the real file for the instant before the second
  check closes it.
- Edits written through a descriptor passed over a Unix socket (`SCM_RIGHTS`) are merged only
  when a descriptor the grate knows of closes.

## Building

```bash
cd rust-grates/user-view-grate
cargo lind_compile --release --output-dir grates
```

## Testing

The policy parser, the view rendering and merging, and the descriptor tracking are plain Rust
with unit tests that run on the build host:

```bash
cd rust-grates/user-view-grate
cargo test
```

The grate itself is tested inside lind-wasm, from the repository root:

```bash
make test GRATE=user-view-grate
```

Four runs share one policy (`test/uvg_test.conf`):

| Run | As | Checks |
|---|---|---|
| `uvg_shadow_test.c` | `--user alice` | One-line view through every kind of path; rewriting her line; edits for other users refused; truncate, unlink and rename refused; merges through `dup`, `fork` and `dup2`. |
| `uvg_raw_test.c` | `--user root` | The real file after the run above: alice's line changed in place, the others byte for byte as before. |
| `uvg_redact_test.c` | `--user support` | Masked card numbers and tokens, dropped lines, hidden CSV columns, `deny`, unnamed user, `readonly`. |
| `uvg_uid_test.c` | effective uid | A cage identified by uid adds and removes its own line and cannot add one for another uid. |

## Code layout

- `src/main.rs`: options, policy loading, handler registration.
- `src/policy.rs`: the policy file.
- `src/view.rs`: rendering a view and merging an edited view back.
- `src/fdtrack.rs`: which descriptors refer to which writable view.
- `src/handlers.rs`: the syscall handlers.
- `src/sys.rs`: the syscalls the grate makes for itself and for a cage.
