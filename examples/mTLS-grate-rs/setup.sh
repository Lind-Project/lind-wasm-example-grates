#!/bin/bash

LINDFS_DIR="$LIND_WASM_ROOT/lindfs"
CERT_DIR="$LINDFS_DIR/certs"
mkdir -p "$CERT_DIR"

# 1. Generate the CA private key
openssl genrsa -out "$CERT_DIR/ca.key" 4096

# 2. Generate the CA root certificate (ca.crt)
openssl req -x509 -new -nodes -key "$CERT_DIR/ca.key" -sha256 -days 3650 -out "$CERT_DIR/ca.crt" -subj "/CN=MyLocalCA"

# 3. Generate the application's private key (key.pem)
openssl genrsa -out "$CERT_DIR/key.pem" 2048

# 4. Generate a Certificate Signing Request (CSR)
openssl req -new -key "$CERT_DIR/key.pem" -out "$CERT_DIR/cert.csr" -subj "/CN=localhost"

# 5. Sign the CSR with your CA to create the final certificate (cert.pem)
openssl x509 -req -in "$CERT_DIR/cert.csr" -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial -out "$CERT_DIR/cert.pem" -days 365 -sha256

# 6. Clean up and Verify
rm "$CERT_DIR/cert.csr" "$CERT_DIR/ca.srl"
openssl verify -CAfile "$CERT_DIR/ca.crt" "$CERT_DIR/cert.pem"

# 7. Execution Commands
# Running the server
#lind mtls-grate --cert "$CERT_DIR/cert.pem" --key "$CERT_DIR/key.pem" --ca "$CERT_DIR/ca.crt" -- echo_server.wasm

# Client connection test
# Note: Ensure the paths match where the client is running from
#openssl s_client -connect 127.0.0.1:443 -cert "$CERT_DIR/cert.pem" -key "$CERT_DIR/key.pem" -CAfile "$CERT_DIR/ca.crt"
