# fs-tee-grate

`fs-tee-grate` runs a target normally, but mirrors selected filesystem syscalls into a secondary
grate stack as well. The primary path decides the return value. The secondary path is there for
comparison, validation, or side effects.

It works by watching the exec chain for `%{` and `%}` markers, identifying the secondary stack,
then rewriting the target cage's handlers so fs calls fan out to both paths.

## Usage

Secondary stack plus target:

```bash
lind-wasm grates/fs-tee-grate.cwasm %{ <secondary-grate>.cwasm %} <target>.cwasm [args...]
```

Example:

```bash
lind-wasm grates/fs-tee-grate.cwasm %{ grates/imfs-grate.cwasm %} exerciser.cwasm
```

The secondary stack can contain one or more grates inside the `%{ ... %}` boundary, for example:

```bash
lind-wasm grates/fs-tee-grate.cwasm %{ <grate-a>.cwasm <grate-b>.cwasm %} <target>.cwasm
```

## Build

```bash
cargo lind_compile --output-dir grates
```
