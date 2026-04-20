# mTLS Grate

Transparently wraps plain TCP connections in mutual TLS. The cage program
performs normal socket operations (connect, accept, read, write) over
unencrypted TCP — the grate intercepts these syscalls and handles the TLS
handshake, encryption, and decryption automatically. The cage has no
knowledge that TLS is happening.

"Mutual TLS" means both sides authenticate: the server presents a certificate
to the client, and the client presents a certificate to the server. This is
enforced by the grate's configuration, not by the cage program.

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
lind-wasm mTLS-grate-rs.cwasm \
  --cert ./certs/cert.pem \
  --key ./certs/key.pem \
  --ca ./certs/ca.crt \
  -- server.cwasm
```

Test with openssl client:
```bash
openssl s_client -ignore_unexpected_eof \
  -connect 127.0.0.1:443 \
  -cert lindfs/certs/cert.pem \
  -key lindfs/certs/key.pem \
  -CAfile lindfs/certs/ca.crt
```

## Building

```bash
cd examples/mTLS-grate-rs
cargo lind_compile
```

## Dependencies

Uses `rustls` 0.23 with the `rustls-rustcrypto` pure-Rust crypto provider
(no assembly, compatible with Lind's WASM runtime).
