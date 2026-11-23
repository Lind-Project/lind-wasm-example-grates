//! crypt-grate: transparent per-file encryption for Lind cages.
//!
//! Regular files the cage opens are stored as AES-256-GCM encrypted 4 KiB
//! blocks; the cage reads and writes plaintext. Meant to run inside
//! fs-routing-clamp so that only one directory tree is encrypted:

mod handlers;
mod sys;

use std::io::Read;

use grate_rs::constants::{
    SYS_FCNTL, SYS_FTRUNCATE, SYS_FXSTAT, SYS_LSEEK, SYS_LSTAT, SYS_MMAP, SYS_NEWFSTATAT, SYS_OPEN,
    SYS_OPENAT, SYS_PREAD, SYS_PREADV, SYS_PWRITE, SYS_PWRITEV, SYS_READ, SYS_READV, SYS_TRUNCATE,
    SYS_WRITE, SYS_WRITEV, SYS_XSTAT,
};
use grate_rs::{GrateBuilder, GrateError};

use crypt_grate::cipher::{ContentCipher, parse_key_file};

const USAGE: &str = "usage: crypt-grate --key-file <path> <program|%}> [args...]\n\
\n\
  --key-file <path>   32 raw bytes, or 64 hex digits (e.g. `openssl rand -hex 32`)\n\
\n\
Run it inside fs-routing-clamp so only files under a prefix are encrypted:\n\
  fs-routing-clamp --prefix /secure %{ crypt-grate --key-file /k.key %} app";

fn fail(msg: &str) -> ! {
    eprintln!("crypt-grate: {msg}\n\n{USAGE}");
    std::process::exit(1);
}

/// Reads the key file without std::fs::read: under Lind, the file size that
/// std gets from metadata can be wrong, and read() preallocates from it.
fn load_key(path: &str) -> [u8; 32] {
    let mut file = std::fs::File::open(path)
        .unwrap_or_else(|e| fail(&format!("cannot open key file {path}: {e}")));
    let mut contents = Vec::new();
    let mut chunk = [0u8; 128];
    loop {
        match file.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                contents.extend_from_slice(&chunk[..n]);
                if contents.len() > 256 {
                    fail(&format!("key file {path} is too large"));
                }
            }
            Err(e) => fail(&format!("cannot read key file {path}: {e}")),
        }
    }
    let key = parse_key_file(&contents).unwrap_or_else(|e| fail(&format!("{path}: {e}")));
    contents.fill(0);
    key
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    // Grate options come first; the first other argument starts the command
    // to exec (under fs-routing-clamp, that is "%}" or the next clamped grate).
    let mut key_path = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--key-file" => {
                key_path = Some(
                    args.get(i + 1)
                        .cloned()
                        .unwrap_or_else(|| fail("--key-file needs a path")),
                );
                i += 2;
            }
            s if s.starts_with("--key-file=") => {
                key_path = Some(s["--key-file=".len()..].to_string());
                i += 1;
            }
            "-h" | "--help" => {
                println!("{USAGE}");
                std::process::exit(0);
            }
            _ => break,
        }
    }
    let command = args[i..].to_vec();
    let key_path = key_path.unwrap_or_else(|| fail("--key-file is required"));
    if command.is_empty() {
        fail("no program to run");
    }

    let mut key = load_key(&key_path);
    let _ = handlers::CIPHER.set(ContentCipher::from_master_key(&key));
    key.fill(0);

    if !command.iter().any(|a| a == "%}") {
        eprintln!(
            "crypt-grate: warning: not running inside fs-routing-clamp; every regular file the \
             program uses (including redirected stdin/stdout) will be treated as encrypted"
        );
    }

    GrateBuilder::new()
        .register(SYS_OPEN, handlers::open_handler)
        .register(SYS_OPENAT, handlers::openat_handler)
        .register(SYS_READ, handlers::read_handler)
        .register(SYS_WRITE, handlers::write_handler)
        .register(SYS_PREAD, handlers::pread_handler)
        .register(SYS_PWRITE, handlers::pwrite_handler)
        .register(SYS_READV, handlers::readv_handler)
        .register(SYS_WRITEV, handlers::writev_handler)
        .register(SYS_PREADV, handlers::preadv_handler)
        .register(SYS_PWRITEV, handlers::pwritev_handler)
        .register(SYS_LSEEK, handlers::lseek_handler)
        .register(SYS_FXSTAT, handlers::fstat_handler)
        .register(SYS_XSTAT, handlers::stat_handler)
        .register(SYS_LSTAT, handlers::lstat_handler)
        .register(SYS_NEWFSTATAT, handlers::fstatat_handler)
        .register(SYS_FTRUNCATE, handlers::ftruncate_handler)
        .register(SYS_TRUNCATE, handlers::truncate_handler)
        .register(SYS_FCNTL, handlers::fcntl_handler)
        .register(SYS_MMAP, handlers::mmap_handler)
        .teardown(|result: Result<i32, GrateError>| {
            if let Err(e) = result {
                eprintln!("crypt-grate: {e:?}");
            }
        })
        .run(command);
}
