//! revoke-grate: revoke file descriptors held by running cages.
//!
//! Usage:
//!   revoke-grate [--log] [--] <program> [args...]

mod abi;
mod handlers;
mod state;
mod utils;

use std::sync::atomic::Ordering;

use grate_rs::{GrateBuilder, GrateError, getcageid};

use utils::rlog;

const USAGE: &str = "Usage: revoke-grate [--log] [--] <program> [args...]";

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
                eprintln!("argument parsing failed: {}", e);
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

    builder
        .preexec(|child: i32| {
            let grate = getcageid();
            let child = child as u64;
            state::add_cage(child, grate);
            rlog!("grate cage {}, child cage {}", grate, child);
        })
        .teardown(|result: Result<i32, GrateError>| {
            if let Err(e) = result {
                eprintln!("grate teardown error: {:?}", e);
            }
        })
        .run(config.argv);
}
