## mTLS Grate

### Usage:

- Sevrer: `lind_run mTLS-grate.cwasm --cert ./certs/cert.pem --key ./certs/key.pem --ca ./certs/ca.crt -- mtls_test.cwasm`
- Client: `openssl s_client -connect 127.0.0.1:443 -cert lindfs/certs/cert.pem -key lindfs/certs/key.pem -CAfile lindfs/certs/ca.crt`
