mod handlers;

use clap::Parser;
use fdtables::init_empty_cage;
use grate_rs::{
    GrateBuilder, GrateError,
    constants::{SYS_ACCEPT, SYS_CONNECT, SYS_READ, SYS_WRITE},
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
#[command(author, version, about = "An mTLS Grate for Lind-Wasm", long_about = None)]
struct Args {
    #[arg(long)]
    cert: String,
    #[arg(long)]
    key: String,
    #[arg(long)]
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
    let args = Args::parse();
    init_empty_cage(grate_rs::getcageid());

    let mut root_cert_store = rustls::RootCertStore::empty();
    for cert in load_certs(&args.ca) {
        root_cert_store.add(cert).unwrap();
    }

    let verifier = WebPkiClientVerifier::builder(root_cert_store.clone().into())
        .build()
        .unwrap();

    let server_certs = load_certs(&args.cert);
    let server_key = load_private_key(&args.key);
    let server_config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(server_certs, server_key)
        .expect("bad client certificate/key");
    SERVER_CONFIG.set(Arc::new(server_config)).unwrap();

    let client_certs = load_certs(&args.cert);
    let client_key = load_private_key(&args.key);
    let client_config = ClientConfig::builder()
        .with_root_certificates(root_cert_store)
        .with_client_auth_cert(client_certs, client_key)
        .expect("bad client certificate/key");
    CLIENT_CONFIG.set(Arc::new(client_config)).unwrap();

    *TLS_SESSIONS.lock().unwrap() = Some(std::collections::HashMap::new());

    GrateBuilder::new()
        .register(SYS_CONNECT, connect_syscall)
        .register(SYS_ACCEPT, accept_syscall)
        .register(SYS_READ, read_syscall)
        .register(SYS_WRITE, write_syscall)
        .teardown(|result: Result<i32, GrateError>| println!("Result: {:#?}", result))
        .run(args.app_args);
}
