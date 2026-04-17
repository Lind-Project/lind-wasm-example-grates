use rustls::{ClientConfig, ClientConnection, ServerConfig, ServerConnection};
use std::io::Read;
use std::sync::Arc;

fn main() {
    println!("[1] Installing crypto provider...");
    rustls::crypto::CryptoProvider::install_default(rustls_rustcrypto::provider())
        .expect("failed to install crypto provider");

    println!("[2] Generating self-signed cert...");
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let cert_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let cert = cert_params.self_signed(&key_pair).unwrap();
    let cert_der = rustls_pki_types::CertificateDer::from(cert.der().to_vec());
    let key_der = rustls_pki_types::PrivateKeyDer::try_from(key_pair.serialize_der()).unwrap();

    println!("[3] Building root cert store...");
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(cert_der.clone()).unwrap();

    println!("[4] Building server config...");
    let server_config = ServerConfig::builder_with_provider(rustls_rustcrypto::provider().into())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der.clone_key())
        .expect("bad server config");

    println!("[5] Building client config...");
    let client_config = ClientConfig::builder_with_provider(rustls_rustcrypto::provider().into())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    println!("[6] Creating server connection...");
    let mut server_conn = ServerConnection::new(Arc::new(server_config)).unwrap();

    println!("[7] Creating client connection...");
    let mut client_conn = ClientConnection::new(
        Arc::new(client_config),
        "localhost".try_into().unwrap(),
    ).unwrap();

    println!("[8] Starting TLS handshake...");
    let mut buf = Vec::new();

    // Client hello
    println!("[8a] Client write_tls...");
    client_conn.write_tls(&mut buf).unwrap();
    println!("[8b] Client hello: {} bytes", buf.len());

    println!("[8c] Server read_tls...");
    server_conn.read_tls(&mut &buf[..]).unwrap();
    buf.clear();

    println!("[8d] Server process_new_packets...");
    server_conn.process_new_packets().unwrap();

    // Server hello
    println!("[8e] Server write_tls...");
    server_conn.write_tls(&mut buf).unwrap();
    println!("[8f] Server hello: {} bytes", buf.len());

    println!("[8g] Client read_tls...");
    client_conn.read_tls(&mut &buf[..]).unwrap();
    buf.clear();

    println!("[8h] Client process_new_packets...");
    client_conn.process_new_packets().unwrap();

    // Client finished
    println!("[8i] Client write_tls...");
    client_conn.write_tls(&mut buf).unwrap();
    println!("[8j] {} bytes", buf.len());

    println!("[8k] Server read_tls...");
    server_conn.read_tls(&mut &buf[..]).unwrap();
    buf.clear();

    println!("[8l] Server process_new_packets...");
    server_conn.process_new_packets().unwrap();

    // Server finished
    println!("[8m] Server write_tls...");
    server_conn.write_tls(&mut buf).unwrap();

    println!("[8n] Client read_tls...");
    client_conn.read_tls(&mut &buf[..]).unwrap();
    buf.clear();

    println!("[8o] Client process_new_packets...");
    client_conn.process_new_packets().unwrap();

    println!("[9] TLS handshake complete!");

    // Send application data
    println!("[10] Writing application data...");
    let mut writer = client_conn.writer();
    writer.write_all(b"Hello from client!").unwrap();
    drop(writer);

    client_conn.write_tls(&mut buf).unwrap();
    server_conn.read_tls(&mut &buf[..]).unwrap();
    server_conn.process_new_packets().unwrap();

    let mut plaintext = [0u8; 128];
    let n = server_conn.reader().read(&mut plaintext).unwrap();
    println!("[11] Server received: {}", std::str::from_utf8(&plaintext[..n]).unwrap());

    println!("[12] PASS");
}
