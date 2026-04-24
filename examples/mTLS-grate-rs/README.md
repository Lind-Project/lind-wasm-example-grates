# mTLS Grate

Transparently wraps plain TCP connections in mutual TLS. The cage program
performs normal socket operations (connect, accept, read, write) over
unencrypted TCP — the grate intercepts these syscalls and handles the TLS
handshake, encryption, and decryption automatically. The cage has no
knowledge that TLS is happening.

"Mutual TLS" means both sides authenticate: the server presents a certificate
to the client, and the client presents a certificate to the server. This is
enforced by the grate's configuration, not by the cage program.

## Use case

Legacy or unmodified programs that don't implement TLS can be wrapped with
this grate to get encrypted, mutually-authenticated connections without any
code changes. For example:

- A database client that only speaks plain TCP can be sandboxed behind
  mTLS to encrypt traffic to the database server.
- A microservice that communicates over plain HTTP can get mTLS
  enforcement at the sandbox boundary.
- Combined with `net-namespace-grate`, mTLS can be scoped to specific
  ports — e.g., only encrypt traffic to port 5432 while leaving local
  connections unaffected.

Certificate management is handled outside the cage: the grate operator
provides cert/key/CA paths at launch. The cage program never sees or
manages any cryptographic material.

## How it works

1. **connect()**: The grate forwards the TCP connect, then performs a TLS
   client handshake on the established socket. A `ClientConnection` is
   created and stored in the session map.

2. **accept()**: The grate forwards the TCP accept, then performs a TLS
   server handshake on the new socket. A `ServerConnection` is created
   and stored in the session map.

3. **write()**: For TLS-wrapped fds, the grate encrypts the plaintext
   via rustls and writes the ciphertext to the real socket.

4. **read()**: For TLS-wrapped fds, the grate reads ciphertext from the
   real socket, decrypts via rustls, and copies plaintext to the cage's
   buffer.

5. **close()**: Tears down the TLS session (sends close_notify) and
   cleans up the session map entry.

Non-TLS fds (e.g. files, pipes) pass through unchanged.

## Usage

Server side:
```bash
lind_run mTLS-grate-rs.cwasm \
  --server-cert /certs/server.crt \
  --server-key /certs/server.key \
  --ca /certs/ca.crt \
  -- server.cwasm
```

Test with openssl client (from the host, not inside Lind):
```bash
lind_run mTLS-grate-rs.cwasm \
  --client-cert /certs/client.crt \
  --client-key /certs/client.key \
  --ca /certs/ca.crt \
  -- client.cwasm
```

Note: only the CA certificate (`ca.crt`) needs to be shared between
server and client. Each side has its own cert and private key.

## Certificate setup

Generate test certificates and install dependencies:
```bash
bash test/setup.sh
```

This creates a self-signed CA and a server certificate in
`$LIND_WASM_ROOT/lindfs/certs/`. For production, use proper CA-signed
certificates.

## Building

```bash
cd examples/mTLS-grate-rs
cargo lind_compile
```

## Testing
```bash
lind_compile -s test/mtls_server_test.c
lind_compile -s test/mtls_client_test.c

bash test/test.sh
```

## Dependencies

Uses `rustls` 0.23 with the `rustls-rustcrypto` pure-Rust crypto provider
(no assembly, compatible with Lind's WASM runtime).
Uses tcpdump as part of the test to verify encrypted stream.
