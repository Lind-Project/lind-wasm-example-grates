mod handlers;
mod nanny;
mod resources;

use std::sync::OnceLock;

use grate_rs::constants::*;
use grate_rs::GrateBuilder;

use nanny::NannyState;
use resources::ResourceConfig;

/// Global nanny state, initialised once before the grate runs.
pub static NANNY: OnceLock<NannyState> = OnceLock::new();

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Usage: resource-grate-rs <resource_file> <cage_binary> [cage_args...]
    // Or:    resource-grate-rs <cage_binary> [cage_args...]  (reads RESOURCE_CONFIG env)
    let (config_path, cage_args) = if args.len() >= 3 {
        // First arg is the config file.
        (args[1].clone(), args[2..].to_vec())
    } else if args.len() >= 2 {
        // No config file arg — try RESOURCE_CONFIG env var.
        match std::env::var("RESOURCE_CONFIG") {
            Ok(path) => (path, args[1..].to_vec()),
            Err(_) => {
                eprintln!(
                    "Usage: {} <resource_file> <cage_binary> [cage_args...]",
                    args[0]
                );
                eprintln!("   or: RESOURCE_CONFIG=<file> {} <cage_binary> [cage_args...]", args[0]);
                std::process::exit(1);
            }
        }
    } else {
        eprintln!(
            "Usage: {} <resource_file> <cage_binary> [cage_args...]",
            args[0]
        );
        std::process::exit(1);
    };

    // Parse resource config and initialise global nanny state.
    let config = ResourceConfig::parse_file(&config_path);
    NANNY
        .set(NannyState::from_config(config))
        .unwrap_or_else(|_| panic!("NANNY already initialised"));

    println!("[ResourceGrate] Loaded config from: {}", config_path);

    // Register all syscall handlers and run the cage.
    let builder = GrateBuilder::new()
        // File I/O
        .register(SYS_OPEN, handlers::handle_open)
        .register(SYS_CLOSE, handlers::handle_close)
        .register(SYS_READ, handlers::handle_read)
        .register(SYS_WRITE, handlers::handle_write)
        .register(SYS_PREAD, handlers::handle_pread64)
        .register(SYS_PWRITE, handlers::handle_pwrite64)
        .register(SYS_READV, handlers::handle_readv)
        .register(SYS_WRITEV, handlers::handle_writev)
        // Network
        .register(SYS_SOCKET, handlers::handle_socket)
        .register(SYS_BIND, handlers::handle_bind)
        .register(SYS_LISTEN, handlers::handle_listen)
        .register(SYS_ACCEPT, handlers::handle_accept)
        .register(SYS_CONNECT, handlers::handle_connect)
        .register(SYS_SENDTO, handlers::handle_sendto)
        .register(SYS_RECVFROM, handlers::handle_recvfrom)
        .register(SYS_SENDMSG, handlers::handle_sendmsg)
        .register(SYS_RECVMSG, handlers::handle_recvmsg)
        // Threading
        .register(SYS_CLONE, handlers::handle_clone)
        .register(SYS_EXIT, handlers::handle_exit)
        // Random
        .register(SYS_GETRANDOM, handlers::handle_getrandom)
        // Teardown
        .teardown(|result| {
            match result {
                Ok(status) => println!("[ResourceGrate] Cage exited with status {}", status),
                Err(e) => eprintln!("[ResourceGrate] Error: {:?}", e),
            }
        });

    println!("[ResourceGrate] Starting cage: {}", cage_args.join(" "));
    builder.run(cage_args);
}
