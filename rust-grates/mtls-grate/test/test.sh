#!/bin/bash
set -e

# The path inside the Lind Sandbox where the keys live
CAGE_CERT_DIR="/certs"
PORT=8081
PCAP_FILE="mtls_traffic.pcap"

echo "=== Phase 1: Initializing Network Capture ==="
# Start capturing loopback traffic on the target port
# (Requires sudo privileges on the host machine to bind tcpdump)
echo "[Host] Starting tcpdump on port $PORT..."
sudo tcpdump -i lo port $PORT -w $PCAP_FILE -q &
TCPDUMP_PID=$!

# Give tcpdump a second to bind to the interface
sleep 1

echo ""
echo "=== Phase 2: Booting the Lind mTLS Server ==="
# Notice we ONLY pass the server keys here now!
lind_run mTLS-grate-rs.cwasm \
    --server-cert $CAGE_CERT_DIR/server.crt \
    --server-key $CAGE_CERT_DIR/server.key \
    --ca $CAGE_CERT_DIR/ca.crt \
    -- mtls_server_test.cwasm &
SERVER_PID=$!

# Give the server a moment to bind and listen
sleep 2

echo ""
echo "=== Phase 3: Booting the Lind mTLS Client ==="
# Notice we ONLY pass the client keys here now!
lind_run mTLS-grate-rs.cwasm \
    --client-cert $CAGE_CERT_DIR/client.crt \
    --client-key $CAGE_CERT_DIR/client.key \
    --ca $CAGE_CERT_DIR/ca.crt \
    -- mtls_client_test.cwasm

echo ""
echo "=== Phase 4: Cleaning Up ==="
# Wait for the background server to cleanly shut down
wait $SERVER_PID 2>/dev/null || true

# Kill the packet capture and flush it to disk
sudo kill $TCPDUMP_PID
sleep 1 

echo ""
echo "=== Phase 5: Encryption Verification ==="
# We search the raw bytes of the pcap file for the exact strings the C code wrote.
SERVER_MSG="Hello from the Lind mTLS Server!"
CLIENT_MSG="Hello from the Lind mTLS Client!"

echo "Scanning raw network packets for leaked plaintext..."
LEAKED=0

if strings $PCAP_FILE | grep -q "$SERVER_MSG"; then
    echo " FAIL: Server plaintext found on the wire! Interposition failed."
    LEAKED=1
fi

if strings $PCAP_FILE | grep -q "$CLIENT_MSG"; then
    echo " FAIL: Client plaintext found on the wire! Interposition failed."
    LEAKED=1
fi

if [ $LEAKED -eq 0 ]; then
    echo " PASS: No plaintext found in the packet capture."
    echo " PASS: Data successfully verified as encrypted ciphertext on the wire."
fi

# Cleanup the capture file so it doesn't clutter your directory
rm -f $PCAP_FILE
