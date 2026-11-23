//! FS Event Clamp
//!
//! Runs the program outside of the clamped grates until it successfully opens a path matching a
//! regex. From then on (sticky, inherited by children), every syscall the clamped grates
//! registered for the program is routed to them.
//!
//! Usage: fs-event-clamp --regex 'secret[.]txt$' %{ audit-grate %} program [args...]

mod handlers;
mod state;

use grate_rs::constants::*;
use grate_rs::{GrateBuilder, GrateError, getcageid};
use regex::bytes::Regex;

const USAGE: &str = "Usage: fs-event-clamp --regex <regex> %{ <grates...> %} <program> [args...]";

#[derive(Debug)]
struct Config {
    regex: Regex,
    /// [clamped grates..., "%}", program, args...]
    exec_chain: Vec<String>,
}

fn parse_argv(args: &[String]) -> Result<Config, String> {
    let mut regex = None;
    let mut iter = args.iter();
    loop {
        let pattern = match iter.next().map(String::as_str) {
            Some("%{") => break,
            Some("--regex") => iter.next().ok_or("--regex requires an argument")?,
            Some(arg) => arg
                .strip_prefix("--regex=")
                .ok_or_else(|| format!("unexpected argument: {arg}"))?,
            None => return Err("missing %{ ... %} block".into()),
        };
        regex = Some(Regex::new(pattern).map_err(|e| format!("invalid --regex: {e}"))?);
    }
    let regex = regex.ok_or("missing --regex")?;
    let exec_chain: Vec<String> = iter.cloned().collect();
    match exec_chain.iter().position(|a| a == "%}") {
        Some(end) if end + 1 < exec_chain.len() => Ok(Config { regex, exec_chain }),
        Some(_) => Err("missing program after %}".into()),
        None => Err("missing %} in command line".into()),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let config = parse_argv(&args).unwrap_or_else(|e| {
        eprintln!("argument error: {e}\n{USAGE}");
        std::process::exit(1);
    });

    state::init(getcageid(), config.regex);

    GrateBuilder::new()
        .register(SYS_EXEC, handlers::exec_handler)
        .register(SYS_CLONE, handlers::fork_handler::<SYS_CLONE>)
        .register(SYS_EXIT_GROUP, handlers::exit_handler)
        .register(SYS_REGISTER_HANDLER, handlers::register_handler_handler)
        .teardown(|result: Result<i32, GrateError>| {
            if let Err(e) = result {
                eprintln!("[fs-event-clamp] error: {e:?}");
            }
        })
        .run(config.exec_chain);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Config, String> {
        parse_argv(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn parses_regex_and_exec_chain() {
        for args in [
            &["--regex", "secret$", "%{", "audit", "%}", "app"][..],
            &["--regex=secret$", "%{", "audit", "%}", "app"],
        ] {
            let config = parse(args).unwrap();
            assert!(config.regex.is_match(b"/tmp/secret"));
            assert_eq!(config.exec_chain, ["audit", "%}", "app"]);
        }
    }

    #[test]
    fn rejects_malformed_command_lines() {
        for args in [
            &[][..],
            &["%{", "audit", "%}", "app"],
            &["--regex", "[", "%{", "audit", "%}", "app"],
            &["--regex"],
            &["--regex", "x", "audit", "%}", "app"],
            &["--regex", "x", "%{", "audit", "app"],
            &["--regex", "x", "%{", "audit", "%}"],
        ] {
            assert!(parse(args).is_err(), "{args:?}");
        }
    }
}
