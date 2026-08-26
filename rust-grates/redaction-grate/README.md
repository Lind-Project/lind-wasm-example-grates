# redaction-grate

`redaction-grate` masks configured literal strings in data written through:

- `write`
- `pwrite`
- `writev`

Usage:

```sh
lind-wasm grates/redaction-grate.cwasm --redact secret --redact token -- app.cwasm
```

Each matched byte is replaced with `*` by default, preserving the original
write length. Use `--mask X` to choose a different single-byte mask.
