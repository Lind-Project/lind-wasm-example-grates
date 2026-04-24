mod handlers;

use clap::Parser;
use fdtables::init_empty_cage;
use grate_rs::{
    GrateBuilder, GrateError,
    constants::{
        SYS_ACCEPT, SYS_CLONE, SYS_CLOSE, SYS_CONNECT, SYS_DUP, SYS_DUP2, SYS_EXECVE, SYS_READ,
        SYS_WRITE,
    },
};
use handlers::*;
use rustls::{ClientConfig, ServerConfig};
use std::sync::Arc;

use rustls::server::WebPkiClientVerifier;
use rustls_pemfile::{certs, private_key};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::fs::File;
use std::io::BufReader;

#[derive(Parser, Debug)]
#[command(author, version, about = "A Production mTLS Grate for Lind-Wasm", long_about = None)]
struct Args {
    #[arg(long, help = "Path to the Server's public certificate")]
    server_cert: Option<String>,
    #[arg(long, help = "Path to the Server's private key")]
    server_key: Option<String>,
    #[arg(long, help = "Path to the Client's public certificate")]
    client_cert: Option<String>,
    #[arg(long, help = "Path to the Client's private key")]
    client_key: Option<String>,
    #[arg(long, help = "Path to the Certificate Authority root")]
    ca: String,
    #[arg(last = true)]
    app_args: Vec<String>,
}

fn load_certs(filename: &str) -> Vec<CertificateDer<'static>> {
    let file =
        File::open(filename).unwrap_or_else(|_| panic!("cannot open cert file: {}", filename));
    let mut reader = BufReader::new(file);
    certs(&mut reader).map(|result| result.unwrap()).collect()
}

fn load_private_key(filename: &str) -> PrivateKeyDer<'static> {
    let file =
        File::open(filename).unwrap_or_else(|_| panic!("cannot open key file: {}", filename));
    let mut reader = BufReader::new(file);
    private_key(&mut reader).unwrap().expect("no keys found")
}

fn main() {
    rustls::crypto::CryptoProvider::install_default(rustls_rustcrypto::provider())
        .expect("failed to install crypto provider");

    let args = Args::parse();
    init_empty_cage(grate_rs::getcageid());

    // 1. Load the shared Certificate Authority
    let mut root_cert_store = rustls::RootCertStore::empty();
    for cert in load_certs(&args.ca) {
        root_cert_store.add(cert).unwrap();
    }

    // 2. Configure the Server Identity (Used for SYS_ACCEPT)
    // Only initialized if the server arguments are provided
    if let (Some(cert_path), Some(key_path)) = (&args.server_cert, &args.server_key) {
        let verifier = WebPkiClientVerifier::builder(root_cert_store.clone().into())
            .build()
            .unwrap();

        let server_certs = load_certs(cert_path);
        let server_key = load_private_key(key_path);
        let server_config =
            ServerConfig::builder_with_provider(rustls_rustcrypto::provider().into())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_client_cert_verifier(verifier)
                .with_single_cert(server_certs, server_key)
                .expect("bad server certificate/key");

        SERVER_CONFIG.set(Arc::new(server_config)).unwrap();
    }

    // 3. Configure the Client Identity (Used for SYS_CONNECT)
    // Only initialized if the client arguments are provided
    if let (Some(cert_path), Some(key_path)) = (&args.client_cert, &args.client_key) {
        let client_certs = load_certs(cert_path);
        let client_key = load_private_key(key_path);
        let client_config =
            ClientConfig::builder_with_provider(rustls_rustcrypto::provider().into())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(root_cert_store)
                .with_client_auth_cert(client_certs, client_key)
                .expect("bad client certificate/key");

        CLIENT_CONFIG.set(Arc::new(client_config)).unwrap();
    }

    *TLS_SESSIONS.lock().unwrap() = Some(std::collections::HashMap::new());

    GrateBuilder::new()
        .register(SYS_CONNECT, connect_syscall)
        .register(SYS_ACCEPT, accept_syscall)
        .register(SYS_READ, read_syscall)
        .register(SYS_WRITE, write_syscall)
        .register(SYS_CLONE, fork_syscall)
        .register(SYS_EXECVE, exec_syscall)
        .register(SYS_DUP, dup_syscall)
        .register(SYS_DUP2, dup2_syscall)
        .register(SYS_CLOSE, close_syscall)
        .preexec(|cageid: i32| {
            fdtables::init_empty_cage(cageid as u64);
            for fd in 0..3u64 {
                let _ = fdtables::get_specific_virtual_fd(cageid as u64, fd, 0, fd, false, 0);
            }
        })
        .teardown(|result: Result<i32, GrateError>| println!("Result: {:#?}", result))
        .run(args.app_args);
}
