# testing-grate

`testing-grate` is a minimal configurable grate for quickly interposing selected syscall numbers during experiments. It lets you define per-syscall behavior at launch time so you can force fixed return values for some syscalls and pass others through to the normal Lind path without writing a custom grate for each case.

## Example Usage

Run a cage with syscall rules via `-s`:

```bash
testing-grate -s 2:10,4:,233:7 <cage> [cage args...]
```

Rules format:
- `<syscall>:<constant>` returns that constant from the handler.
- `<syscall>:` passes the syscall through by calling `make_threei_call`.
- entries are comma-separated.

Example meaning:
- `2:10` interposes syscall `2` and returns `10`.
- `4:` interposes syscall `4` and forwards it to the normal syscall path.
- `233:7` interposes syscall `233` and returns `7`.
