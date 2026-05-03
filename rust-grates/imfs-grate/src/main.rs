//! IMFS Grate — In-Memory Filesystem for Lind.
//!
//! This grate intercepts filesystem syscalls (open, close, read, write, lseek,
//! fcntl, unlink, pread, pwrite) and handles them with an in-memory filesystem.
//!
//! Usage: imfs-grate <cage_binary> [args...]
//!
//! Environment variables:
//!   PRELOADS — colon-separated list of host files to load into IMFS at startup.

mod handlers;
mod imfs;
mod logging;

use grate_rs::constants::*;
use grate_rs::{GrateBuilder, GrateError};

struct Config {
    argv: Vec<String>,
    log_enabled: bool,
}

fn parse_argv(args: Vec<String>) -> Config {
    let mut log_enabled = false;
    let mut i = 0;

    while i < args.len() {
        if args[i] == "--log" {
            log_enabled = true;
            i += 1;
        } else {
            break;
        }
    }

    Config {
        argv: args[i..].to_vec(),
        log_enabled,
    }
}

fn main() {
    let config = parse_argv(std::env::args().skip(1).collect());
    logging::init(config.log_enabled);

    // Initialize the in-memory filesystem.
    imfs::init();

    // Load files from the host filesystem into IMFS before cage execution.
    if let Ok(preloads) = std::env::var("PRELOADS") {
        load_preloads(&preloads);
    }

    // Build and run the grate. Registers handlers for all filesystem syscalls,
    // forks a child cage, and waits for it to exit.
    GrateBuilder::new()
        .register(SYS_OPEN, handlers::open_handler)
        .register(SYS_CLOSE, handlers::close_handler)
        .register(SYS_READ, handlers::read_handler)
        .register(SYS_WRITE, handlers::write_handler)
        .register(SYS_LSEEK, handlers::lseek_handler)
        .register(SYS_FCNTL, handlers::fcntl_handler)
        .register(SYS_UNLINK, handlers::unlink_handler)
        .register(SYS_LINK, handlers::link_handler)
        .register(SYS_PREAD, handlers::pread_handler)
        .register(SYS_PWRITE, handlers::pwrite_handler)
        .register(SYS_MKDIR, handlers::mkdir_handler)
        .register(SYS_CLONE, handlers::fork_handler)
        .register(SYS_EXEC, handlers::exec_handler)
        .teardown(|result: Result<i32, GrateError>| {
            log!("exited: {:?}", result);
        })
        .run(config.argv);
}

/// Load files from the host filesystem into IMFS.
///
/// The PRELOADS env var is a colon-separated list of paths.
/// Each file is read from the host and written into IMFS at the same path,
/// creating parent directories as needed.
fn load_preloads(preloads: &str) {
    for path in preloads.split(':') {
        if path.is_empty() {
            continue;
        }

        log!("preloading: {}", path);

        // Read the file from the host filesystem.
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(e) => {
                log!("failed to read {}: {}", path, e);
                continue;
            }
        };

        imfs::with_imfs(|state| {
            // Create parent directories.
            let mut dir_path = String::new();
            for component in path.split('/').filter(|s| !s.is_empty()) {
                dir_path.push('/');
                dir_path.push_str(component);

                // Try to create as directory — will fail silently if it exists or
                // if this is the final component (a file).
                if dir_path != path {
                    let _ = state.mkdir(&dir_path, 0o755);
                }
            }

            // Use cage_id 0 for preloading (before any cage exists).
            fdtables::init_empty_cage(0);

            // Create and write the file.
            let fd = state.open(0, path, fs::O_CREAT | fs::O_WRONLY, 0o777);
            if fd >= 0 {
                state.write(0, fd as u64, &data);
                state.close(0, fd as u64);
            }
        });
    }
}
