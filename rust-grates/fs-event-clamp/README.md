# fs-event-clamp

Runs a program **outside** a set of clamped grates until it successfully opens
a file whose pathname matches a regex. From then on, every syscall those
grates registered handlers for is routed to them. The switch is per cage and
cannot be undone.

The intended use is extra scrutiny after a cage touches a secret: an
Audit-Grate watches reads and writes once the cage has opened the secret file,
but costs nothing before that.

```bash
lind-wasm grates/fs-event-clamp.cwasm --regex '(^|/)secret[.]txt$' %{ \
  grates/audit-grate.cwasm \
%} myapp.cwasm
```

## Behavior

- Before activation, syscalls bypass the clamped grates. They still go through
  any grates outside fs-event-clamp.
- A **successful** `open`/`openat` whose pathname argument matches the regex
  activates the cage. The triggering open itself is not routed. Failed opens,
  `stat`, etc. never activate.
- After activation, every syscall the clamped grates registered is routed to
  them. This includes non-filesystem calls and descriptors opened before
  activation. Syscalls they did not register still bypass them.
- Activation survives `close` and `exec`. Children forked after activation are
  activated; children forked before stay independent. A child activating does
  not activate its parent or siblings.
- Handlers the clamped grates register for the program at runtime are deferred
  until activation, and installed immediately after.
- The regex uses Rust `regex::bytes` syntax on the raw pathname argument (no
  canonicalization, `openat` dirfds and symlinks are not resolved). Anchor it
  when you need a full-path match.
- If activation fails, the triggering open returns the error, so the program
  never continues unaudited after opening the secret. The descriptor it opened
  is not closed, however.

The clamped grates need no changes: fs-event-clamp only observes and replays
their own `register_handler` calls. Judging what is read or written is the
Audit-Grate's job.

## How it works

1. **Startup**: forks a child cage and installs handlers for `exec`, `clone`, `exit_group`
   and `register_handler` (1001) on it.
2. **Setup**: the child execs the grates inside `%{ ... %}`. Every
   `register_handler` they issue is forwarded unchanged and recorded, together
   with the fork tree of those cages. Nested `%{`/`%}` blocks are tracked so
   the right `%}` ends the setup.
3. **`%}`**: the cage reaching it becomes the program. fs-event-clamp:
   - computes the handler set the cage would have inherited from the clamped
     grates (its own registrations overriding its ancestors', just like 3i
     handler-table inheritance on fork) and keeps it pending;
   - replaces the cage's handler table with fs-event-clamp's own table (the
     outer composition), plus `open`/`openat` observers and the lifecycle
     handlers;
   - execs the real program.
4. **Activation**: when an observed open succeeds on a matching path, the
   pending handlers are registered on the cage on behalf of the grates that
   originally requested them.

Clamped grates that interpose on lifecycle syscalls forward them through their
own handler table, which was inherited from fs-event-clamp's child. So the
clamp keeps seeing `fork`/`exec`/`exit`/`register_handler` after activation.

## Building and testing

```bash
cd rust-grates/fs-event-clamp
cargo test                                    # host unit tests
cargo lind_compile --release --output-dir grates
```

Integration tests are listed in `test/grates_test.toml` (`bash test/run_tests.sh fs-event-clamp`
from the repository root). They use `testing-grate` as the audit grate.

### Dummy Audit-Grate

`test/audit_grate.c` is an existing grate that fs-event-clamp knows nothing
about. It denies reads, writes and opens, answers `geteuid` and a custom
syscall 2048, and registers syscall 2049 at runtime from its `geteuid` handler:

```bash
lind_compile -s --compile-grate --output-dir grates test/audit_grate.c
lind_compile -s test/fs_event_clamp_test.c
lind-wasm grates/fs-event-clamp.cwasm --regex '(null|not-a-real-secret)$' %{ \
  grates/audit_grate.cwasm \
%} fs_event_clamp_test.cwasm --dummy-audit
```

## Code layout

- `src/main.rs`: argument parsing and grate startup.
- `src/state.rs`: registration/fork-tree bookkeeping and activation state
  (unit tested).
- `src/handlers.rs`: 3i handlers for lifecycle syscalls, `%}` handling and the
  `open`/`openat` trigger.
