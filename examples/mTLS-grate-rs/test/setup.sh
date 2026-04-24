#!/bin/bash

# Ensure LIND_WASM_ROOT is set, fallback to current directory if not
LINDFS_DIR="${LIND_WASM_ROOT:-.}/lindfs"
CERT_DIR="$LINDFS_DIR/certs"
mkdir -p "$CERT_DIR"

echo "Installing Dependencies..."
# ==========================================
# 1. Install Test Dependency
# ==========================================

sudo apt-get update -y
sudo apt-get install tcpdump -y

echo "Generating Production mTLS Certificates for Lind-Wasm..."

# ==========================================
# 1. Certificate Authority (CA)
# ==========================================
# Generate the CA private key
openssl genrsa -out "$CERT_DIR/ca.key" 4096

# Generate the CA root certificate (ca.crt)
openssl req -x509 -new -nodes -key "$CERT_DIR/ca.key" -sha256 -days 3650 -out "$CERT_DIR/ca.crt" \
  -subj "/CN=LindLocalCA" \
  -addext "basicConstraints=critical,CA:TRUE"

echo "[#] Certificate Authority generated."

# ==========================================
# 2. Server Identity
# ==========================================
# Generate the Server's private key and CSR
openssl genrsa -out "$CERT_DIR/server.key" 2048
openssl req -new -key "$CERT_DIR/server.key" -out "$CERT_DIR/server.csr" \
  -subj "/CN=localhost"

# Create the v3 extension file for the Server
# Rustls requires SANs and the serverAuth extendedKeyUsage
cat <<EOF > "$CERT_DIR/server_v3.ext"
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
EOF

# Sign the Server CSR with the CA
openssl x509 -req -in "$CERT_DIR/server.csr" -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" \
  -CAcreateserial -out "$CERT_DIR/server.crt" -days 365 -sha256 -extfile "$CERT_DIR/server_v3.ext"

echo "[#] Server certificate generated."

# ==========================================
# 3. Client Identity
# ==========================================
# Generate the Client's private key and CSR
openssl genrsa -out "$CERT_DIR/client.key" 2048
openssl req -new -key "$CERT_DIR/client.key" -out "$CERT_DIR/client.csr" \
  -subj "/CN=lind-client-01"

# Create the v3 extension file for the Client
# Requires the clientAuth extendedKeyUsage
cat <<EOF > "$CERT_DIR/client_v3.ext"
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
extendedKeyUsage = clientAuth
subjectAltName = DNS:lind-client-01
EOF

# Sign the Client CSR with the CA
openssl x509 -req -in "$CERT_DIR/client.csr" -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" \
  -CAcreateserial -out "$CERT_DIR/client.crt" -days 365 -sha256 -extfile "$CERT_DIR/client_v3.ext"

echo "[#] Client certificate generated."

# ==========================================
# 4. Cleanup and Verification
# ==========================================
rm "$CERT_DIR"/server.csr "$CERT_DIR"/client.csr "$CERT_DIR"/ca.srl "$CERT_DIR"/*_v3.ext

echo "------------------------------------------------"
echo "Verifying Server Certificate:"
openssl verify -CAfile "$CERT_DIR/ca.crt" "$CERT_DIR/server.crt"
echo "Verifying Client Certificate:"
openssl verify -CAfile "$CERT_DIR/ca.crt" "$CERT_DIR/client.crt"
echo "------------------------------------------------"
echo "Certificates successfully generated in $CERT_DIR"
echo ""

# ==========================================
# 5. Execution Commands
# ==========================================
echo "# 1. Run the Lind-Wasm mTLS Server (Terminal 1):"
echo "lind_run mTLS-grate-rs.cwasm \\"
echo "  --server-cert /certs/server.crt \\"
echo "  --server-key /certs/server.key \\"
echo "  --ca /certs/ca.crt \\"
echo "  -- mtls_server_test.cwasm"
echo ""
echo "# 2. Run the Lind-Wasm mTLS Client (Terminal 2):"
echo "lind_run mTLS-grate-rs.cwasm \\"
echo "  --client-cert /certs/client.crt \\"
echo "  --client-key /certs/client.key \\"
echo "  --ca /certs/ca.crt \\"
echo "  -- mtls_client_test.cwasm"
