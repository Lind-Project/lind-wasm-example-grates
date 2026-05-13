## readonly-grate

`readonly-grate`  **denies all write-related system calls**. Any attempt to modify file contents will fail with an error (e.g., `EPERM`), making the filesystem effectively read-only.

## Behavior

The following operations are blocked:

- `write`
- `writev`
- `pwrite`

All such calls will return `EPERM`.

## Usage

Run a program under the `readonly-grate` using:
`lind-wasm grates/readonly-grate.cwasm readonly-grate-test.cwasm`
