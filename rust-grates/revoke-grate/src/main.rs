//! revoke-grate: revoke file descriptors held by running cages.
//!
//! Usage:
//!   revoke-grate [--log] [--revoke <cageid>:<fd>[:null|zero] ...] [--] <program> [args...]
//!
//! Cages below the grate revoke fds at runtime with the `revoke` syscall
//! (see abi.rs / include/lind_revoke.h). `--revoke` optionally arms some
//! revocations at startup. A revoked fd behaves like /dev/null (default) or
//! /dev/zero. See README.md for the exact semantics.

mod abi;
mod handlers;
mod state;
mod utils;

use std::sync::atomic::Ordering;

use grate_rs::{GrateBuilder, GrateError, getcageid};

const USAGE: &str = "Usage: revoke-grate [--log] [--revoke <cageid>:<fd>[:null|zero] ...] \
[--] <program> [args...]";

struct Config {
    log: bool,
    argv: Vec<String>,
}

fn parse_args(args: Vec<String>) -> Result<Config, String> {
    let mut log = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--log" => {
                log = true;
                i += 1;
            }
            "--" => {
                i += 1;
                break;
            }
            "-h" | "--help" => return Err(String::new()),
            s if s.starts_with('-') => return Err(format!("unknown option '{}'", s)),
            _ => break,
        }
    }
    let argv = args[i..].to_vec();
    if argv.is_empty() {
        return Err("no program given".into());
    }
    Ok(Config { log, argv })
}

fn main() {
    let config = match parse_args(std::env::args().skip(1).collect()) {
        Ok(c) => c,
        Err(e) => {
            if !e.is_empty() {
                eprintln!("[revoke-grate] {}", e);
            }
            eprintln!("{}", USAGE);
            std::process::exit(2);
        }
    };

    utils::LOG.store(config.log, Ordering::Relaxed);

    let mut builder = GrateBuilder::new();
    for (nr, h) in handlers::handler_table() {
        builder = builder.register(nr, h);
    }

    let log = config.log;
    builder
        .preexec(move |child: i32| {
            let grate = getcageid();
            let child = child as u64;
            state::add_cage(child, grate);
            if log {
                eprintln!("[revoke-grate] grate cage {}, child cage {}", grate, child);
            }
            for ((cage, fd), mode) in state::all() {
                // Cage IDs are allocated increasingly, so only the child and
                // cages created after it can route through this grate.
                if cage < child {
                    eprintln!(
                        "[revoke-grate] warning: cage {} is not a descendant of child cage {}; \
                         {}:{} will never be intercepted",
                        cage, child, cage, fd
                    );
                } else if cage == child && !handlers::fd_is_open(cage, fd) {
                    eprintln!(
                        "[revoke-grate] warning: fd {} is not open in cage {}; \
                         the slot stays revoked if it is opened later",
                        fd, cage
                    );
                }
                if log {
                    eprintln!(
                        "[revoke-grate] revoking cage {} fd {} as {:?}",
                        cage, fd, mode
                    );
                }
            }
        })
        .teardown(|result: Result<i32, GrateError>| {
            if let Err(e) = result {
                eprintln!("[revoke-grate] error: {:?}", e);
            }
        })
        .run(config.argv);
}
