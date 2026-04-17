use rustls::{ClientConfig, ClientConnection, ServerConfig, ServerConnection};
use rustls::server::WebPkiClientVerifier;
use std::io::{Read, Write};
use std::sync::Arc;

fn main() {
    println!("[1] Installing crypto provider...");
    rustls::crypto::CryptoProvider::install_default(rustls_rustcrypto::provider())
        .expect("failed to install crypto provider");

    println!("[2] Generating self-signed cert...");
    let cert_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let cert = cert_params.self_signed(&rcgen::KeyPair::generate().unwrap()).unwrap();
    let cert_der = rustls_pki_types::CertificateDer::from(cert.der().to_vec());
    let key_der = rustls_pki_types::PrivateKeyDer::try_from(
        cert.key_pair.serialize_der()
    ).unwrap();

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
    let mut client_to_server = Vec::new();
    let mut server_to_client = Vec::new();

    // Client writes client hello
    println!("[8a] Client write_tls (client hello)...");
    client_conn.write_tls(&mut client_to_server).unwrap();
    println!("[8b] Client hello: {} bytes", client_to_server.len());

    // Server reads client hello
    println!("[8c] Server read_tls...");
    server_conn.read_tls(&mut &client_to_server[..]).unwrap();
    client_to_server.clear();

    // Server processes client hello
    println!("[8d] Server process_new_packets...");
    server_conn.process_new_packets().unwrap();

    // Server writes server hello
    println!("[8e] Server write_tls (server hello)...");
    server_conn.write_tls(&mut server_to_client).unwrap();
    println!("[8f] Server hello: {} bytes", server_to_client.len());

    // Client reads server hello
    println!("[8g] Client read_tls...");
    client_conn.read_tls(&mut &server_to_client[..]).unwrap();
    server_to_client.clear();

    println!("[8h] Client process_new_packets...");
    client_conn.process_new_packets().unwrap();

    // Continue handshake
    println!("[8i] Client write_tls (finished)...");
    client_conn.write_tls(&mut client_to_server).unwrap();

    println!("[8j] Server read_tls...");
    server_conn.read_tls(&mut &client_to_server[..]).unwrap();
    client_to_server.clear();

    println!("[8k] Server process_new_packets...");
    server_conn.process_new_packets().unwrap();

    println!("[8l] Server write_tls...");
    server_conn.write_tls(&mut server_to_client).unwrap();

    println!("[9] TLS handshake complete!");

    // Send application data
    println!("[10] Sending application data...");
    let mut stream_client = rustls::Stream::new(&mut client_conn, &mut client_to_server);
    stream_client.write_all(b"Hello from client!").unwrap();
    drop(stream_client);

    server_conn.read_tls(&mut &client_to_server[..]).unwrap();
    server_conn.process_new_packets().unwrap();

    let mut buf = [0u8; 128];
    let n = server_conn.reader().read(&mut buf).unwrap();
    let msg = std::str::from_utf8(&buf[..n]).unwrap();
    println!("[11] Server received: {}", msg);

    println!("[12] PASS — rustls works in this environment");
}
