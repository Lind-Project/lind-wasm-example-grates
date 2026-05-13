# testing-grate

`testing-grate` is a minimal runtime configurable grate for interposing selected syscalls helpful for running grate tests. It lets you define per-syscall behavior at launch time so you can force fixed return values for some syscalls and pass others through to the normal Lind path without writing a custom grate for each case.

## Usage

```bash
Usage: testing-grate.cwasm -s <rules> <cage> [cage args...]

Rules: <syscall>:<constant> or <syscall>: (empty means passthrough)

Example:

testing-grate -s 2:10,4:,233:7 <cage> [cage args...]

Meaning:
- `2:10` interposes syscall `2` and return `10` for all calls.
- `4:` interposes syscall `4` and forwards it to the normal syscall path.
- `233:7` interposes syscall `233` and return `7` for all calls.
```
