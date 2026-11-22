# api-key-grate

Lets a program use an API key without ever having it.

An agent's script has to call an API, but should never see the key, so that it cannot leak it
into a log, a prompt or an attacker's URL. Under this grate the script is given a *placeholder*
where it expects the key. When it sends the placeholder to a host the key is allowed to go to,
the grate puts the key in its place. Sent anywhere else, written to a file or printed, the
placeholder stays a placeholder. If the host sends the key back, the script receives the
placeholder. The key itself is only ever in the grate's memory.

```bash
lind-wasm grates/api-key-grate.cwasm --policy keys.conf [--] program [args...]
```

## Policy

```
[key openai]
file /run/keys/openai        # the key is this file's content
env OPENAI_API_KEY           # the program finds the placeholder here
allow 162.159.140.245:443    # the placeholder becomes the key on the way here

[key github]
env GITHUB_TOKEN             # no file: the key is the grate's own GITHUB_TOKEN
allow 140.82.112.0/20:443
allow [2606:50c0::]/32:443
```

Each `[key NAME]` section is one key.

| Directive | Meaning |
|---|---|
| `file PATH` | The key is the content of this file (one trailing newline aside). A program that reads the file reads the placeholder. |
| `env NAME` | The program is started with `NAME` set to the placeholder. Without a `file`, the first `env` also names where the key comes from: the grate's own environment, which `lind-wasm --env NAME` passes in. |
| `allow ADDRESS:PORT` | Where the key may go. `ADDRESS` is an IPv4 address, or an IPv6 address in brackets, optionally with `/BITS` for a network. `PORT` may be `*`. At least one is needed. |

`#` starts a comment.

A placeholder has its key's length, its first four characters and its shape: a letter stays a
letter of the same case, a digit a digit, punctuation stays where it is, and the rest is drawn
at random each time the grate starts. Code that checks what a key looks like accepts it, and
because the lengths are equal, a `Content-Length` computed for the placeholder is right for the
key.

## How it works

**Going out.** A socket that is connected to an allowed address *carries keys*. What the program
sends on it is copied into the grate, the placeholders in the copy are replaced by their keys,
and the copy is what goes out. The address is handled the same way: the grate copies it, checks
the copy, and connects the socket to the copy, so a program cannot show one address and connect
to another.

**Coming in.** What arrives on a socket that carries keys is read into the grate, keys in it are
replaced by placeholders, and only then is it given to the program. A key can arrive split over
two reads, however small the program makes them. Its first part is delivered as the first part
of the placeholder straight away, and the rest follows as the rest: nothing is held back, so a
reply is never delayed, and no read hands over part of a key.

**The key file.** Reads of a key file are answered from the grate's copy of it, in which the key
is the placeholder. Mapping the file, or having the kernel copy it, is refused.

**What a descriptor is.** Whether a call is on a socket that carries keys, or on a key file, is
decided by looking at the descriptor (`fstat`), not by remembering which numbers were connected
or opened. A descriptor that was duplicated, inherited across `fork` or `exec`, or opened under
another name is still the same socket or file.

**A second thread.** A program with several threads can point a descriptor number at something
else (`close`, `dup2`) between the grate looking at it and the call acting on it, hoping to have
a key written into a file, or a reply read without redaction. Calls that use a number and calls
that rebind it are therefore kept apart: a rebinding waits until a write of a key on that number
is done, and waits a moment (up to 20 ms) for reads that were let through untouched.
`src/gate.rs` has the details.

## With TLS

The grate works on the bytes a program sends. A program that does its own TLS sends bytes the
grate cannot read, and nothing in them is replaced. For the key to travel encrypted, the program
speaks plain HTTP and a grate below this one wraps the connection in TLS, which is what
`mtls-grate` does for connections with client certificates:

```bash
lind-wasm grates/mtls-grate.cwasm --ca ca.crt --client-cert c.crt --client-key c.key -- \
  grates/api-key-grate.cwasm --policy keys.conf program
```

With the TLS grate verifying the host's certificate, an `allow` address is also known to be the
host it is meant to be. The tests here run this grate on its own, over plain TCP; the two
grates together are not covered by them.

## Intercepted syscalls

| Category | Syscalls |
|---|---|
| Where a socket goes | connect |
| Going out | write, writev, sendto, sendmsg |
| Coming in | read, readv, recvfrom, recvmsg |
| Rebinding a descriptor | close, dup, dup2, dup3, fcntl |
| Processes | clone, execve, exit_group |
| Key files (only with a `file`) | pread, preadv, mmap, copy_file_range |

A write costs a lookup, and an `fstat` once some socket carries keys. A read costs the same, and
an `fstat` from the start when the policy has a key file.

## Limits

- A placeholder is replaced only when it lies whole within one `write` or `send` (the buffers of
  one `writev` or `sendmsg` count as one). A program that sends it in two calls sends a
  placeholder. HTTP clients send a header in one piece.
- A key is 16 to 4096 printable ASCII characters. Its first four characters are in the
  placeholder, so they are not secret, and neither is which characters are letters and digits.
- Addresses, not host names: a name would have to be resolved by something the grate trusts.
- A key coming back is recognized as the exact bytes of the key. A host that sends it back
  encoded or broken up is not stopped; the host has the key, and this grate is not what keeps it
  honest. A reply that merely ends with more than the first four characters of a key reads as
  the start of the placeholder there.
- Only connected sockets carry keys. `sendto` with an address and `sendmsg` with an address or
  control data go out as the program wrote them.
- A key is read once, when the grate starts. A key file that is replaced while the program runs
  is neither noticed nor protected.
- The grate keeps a program from reading a key file, not from overwriting or removing it. Use
  `readonly-grate` or `write-filter-grate` for that.
- A key that comes from the environment is in the environment of the `lind-wasm` process itself.
- A `writev` or `sendmsg` of more than 1 MiB on a socket that carries keys is a short write.

## Building

```bash
cd rust-grates/api-key-grate
cargo lind_compile --release --output-dir grates
```

## Testing

The policy parser, the trading of keys and placeholders in both directions, and the bookkeeping
are plain Rust with unit tests that run on the build host:

```bash
cd rust-grates/api-key-grate
cargo test
```

The grate itself is tested inside lind-wasm, from the repository root:

```bash
make test GRATE=api-key-grate
```

Each test runs two servers on loopback as child processes, an "API" the policy allows and
another host it does not (`test/akg_common.h`), and plays the program on the client side.

| Run | Checks |
|---|---|
| `akg_test.c` | The environment variable and the key file hold a placeholder, however the file is read. The API receives the key and the other host the placeholder, through `write`, `send`, `writev` and `sendmsg`. A key the API sends back arrives as the placeholder, through `read`, `recv`, `readv` and `recvmsg`, one byte at a time, after a peek, and when it arrives in two parts. A connection is still what it is through `dup`, `fcntl`, `dup2` and `fork`, and a file that takes over its descriptor number gets the placeholder. |
| `akg_race_test.c` | A second thread points the descriptor at a file while the placeholder is being written, and at a connection while a file is being read, a hundred times each with the timing varied. The key is never in the file and never read. With the waiting in `src/gate.rs` taken out, this test finds the key in both. |
| `akg_env_test.c` | The key comes from the environment (`lind-wasm --env`): the program finds the placeholder under that name, and the API still receives the key. |

## Code layout

- `src/main.rs`: options, loading the policy and the keys, handler registration.
- `src/policy.rs`: the policy file, and addresses.
- `src/swap.rs`: placeholders, and trading keys and placeholders in a stream.
- `src/gate.rs`: keeping a descriptor number from being rebound under a call.
- `src/fdtrack.rs`: which descriptors a connection has.
- `src/handlers.rs`: the syscall handlers.
- `src/sys.rs`: the syscalls the grate makes, and copies to and from a cage.
