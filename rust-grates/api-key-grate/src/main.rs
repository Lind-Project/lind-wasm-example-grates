//! api-key-grate: API keys a program can use but never read.
//!
//! The program is given a placeholder where it expects a key. When it sends the placeholder to
//! an address the key is allowed to go to, the grate puts the key in its place. The key itself
//! is only ever in the grate's memory.
//!
//! Usage:
//!   api-key-grate --policy FILE [--] program [args...]

// The syscall side is built only for lind-wasm; the rest also builds, and is tested, natively.
#![cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]

mod fdtrack;
mod gate;
mod policy;
mod swap;

#[cfg(target_arch = "wasm32")]
mod handlers;
#[cfg(target_arch = "wasm32")]
mod sys;

const USAGE: &str = "usage: api-key-grate --policy FILE [--] program [args...]";

#[derive(Debug, PartialEq)]
struct Options {
    policy: String,
    program: Vec<String>,
}

fn parse_args(args: &[String]) -> Result<Options, String> {
    let mut policy = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--" => {
                i += 1;
                break;
            }
            "--policy" => {
                policy = Some(args.get(i + 1).ok_or("--policy needs a file")?.clone());
                i += 2;
            }
            flag if flag.starts_with("--") => return Err(format!("unknown option {flag}")),
            _ => break,
        }
    }
    let program = args[i..].to_vec();
    if program.is_empty() {
        return Err("no program to run".into());
    }
    Ok(Options {
        policy: policy.ok_or("--policy is required")?,
        program,
    })
}

#[cfg(target_arch = "wasm32")]
fn fail(message: String) -> ! {
    eprintln!("api-key-grate: {message}");
    std::process::exit(2);
}

#[cfg(target_arch = "wasm32")]
fn main() {
    use grate_rs::constants::*;
    use grate_rs::{GrateBuilder, GrateError};
    use std::collections::HashMap;

    let args: Vec<String> = std::env::args().skip(1).collect();
    let opts = parse_args(&args).unwrap_or_else(|e| fail(format!("{e}\n{USAGE}")));
    let text = sys::read_file(&opts.policy)
        .unwrap_or_else(|e| fail(format!("cannot read policy {}: errno {}", opts.policy, -e)));
    let policy = policy::Policy::parse(&String::from_utf8_lossy(&text))
        .unwrap_or_else(|e| fail(format!("{}: {e}", opts.policy)));

    // Each key, from its file or from this grate's own environment, and its placeholder.
    let mut secrets = Vec::new();
    let mut files = Vec::new();
    for rule in &policy.keys {
        let content = match &rule.file {
            Some(path) => {
                let read = sys::OwnFd::open(path, fs::O_RDONLY, 0).and_then(|fd| {
                    let st = fd.stat()?;
                    Ok((st, fd.read_all()?))
                });
                let (st, content) = read.unwrap_or_else(|e| {
                    fail(format!(
                        "key {}: cannot read {path}: errno {}",
                        rule.name, -e
                    ))
                });
                if !st.regular {
                    fail(format!("key {}: {path} is not a regular file", rule.name));
                }
                files.push((st.id, content.clone()));
                content
            }
            None => std::env::var(&rule.env[0])
                .map(String::into_bytes)
                .unwrap_or_else(|_| {
                    fail(format!(
                        "key {}: {} is not set in the grate's environment (lind-wasm --env {})",
                        rule.name, rule.env[0], rule.env[0]
                    ))
                }),
        };
        let random = |n: u32| {
            sys::random_below(n)
                .unwrap_or_else(|e| fail(format!("no random numbers: errno {}", -e)))
        };
        let secret = swap::Secret::new(&rule.name, swap::key_text(&content), random)
            .unwrap_or_else(|e| fail(format!("key {}: {e}", rule.name)));
        secrets.push(secret);
    }

    // What the program gets instead: the placeholder, wherever it would have found the key.
    for (rule, secret) in policy.keys.iter().zip(&secrets) {
        for name in &rule.env {
            // The grate has one thread here, and the program it starts inherits this
            // environment. Where the key came from the environment, this overwrites it.
            unsafe {
                std::env::set_var(name, String::from_utf8_lossy(secret.placeholder()).as_ref())
            };
        }
    }
    let views: HashMap<sys::FileId, Vec<u8>> = files
        .into_iter()
        .map(|(id, content)| (id, swap::hide(&secrets, &content)))
        .collect();

    let has_files = !views.is_empty();
    handlers::init(secrets, policy.keys, views);

    let mut grate = GrateBuilder::new()
        .register(SYS_CONNECT, handlers::connect_handler)
        .register(SYS_WRITE, handlers::write_handler)
        .register(SYS_WRITEV, handlers::writev_handler)
        .register(SYS_SENDTO, handlers::sendto_handler)
        .register(SYS_SENDMSG, handlers::sendmsg_handler)
        .register(SYS_READ, handlers::read_handler)
        .register(SYS_READV, handlers::readv_handler)
        .register(SYS_RECVFROM, handlers::recvfrom_handler)
        .register(SYS_RECVMSG, handlers::recvmsg_handler)
        .register(SYS_CLOSE, handlers::close_handler)
        .register(SYS_DUP, handlers::dup_handler)
        .register(SYS_DUP2, handlers::dup2_handler)
        .register(SYS_DUP3, handlers::dup3_handler)
        .register(SYS_FCNTL, handlers::fcntl_handler)
        .register(SYS_CLONE, handlers::clone_handler)
        .register(SYS_EXECVE, handlers::execve_handler)
        .register(SYS_EXIT_GROUP, handlers::exit_group_handler);
    if has_files {
        // The other ways a file's bytes reach a program.
        grate = grate
            .register(SYS_PREAD, handlers::pread_handler)
            .register(SYS_PREADV, handlers::preadv_handler)
            .register(SYS_MMAP, handlers::mmap_handler)
            .register(
                handlers::SYS_COPY_FILE_RANGE,
                handlers::copy_file_range_handler,
            );
    }
    grate
        .teardown(|result: Result<i32, GrateError>| {
            if let Err(e) = result {
                eprintln!("api-key-grate: {e:?}");
            }
        })
        .run(opts.program);
}

#[cfg(not(target_arch = "wasm32"))]
fn main() {
    eprintln!("api-key-grate runs inside lind-wasm. Build it with `cargo lind_compile`.");
    std::process::exit(2);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| w.to_string()).collect()
    }

    #[test]
    fn options_then_the_program() {
        let opts = parse_args(&args(&["--policy", "keys.conf", "agent", "--policy", "x"])).unwrap();
        assert_eq!(opts.policy, "keys.conf");
        // What follows the program's name is the program's.
        assert_eq!(opts.program, ["agent", "--policy", "x"]);

        let opts = parse_args(&args(&["--policy", "p", "--", "--odd-name"])).unwrap();
        assert_eq!(opts.program, ["--odd-name"]);
    }

    #[test]
    fn bad_options() {
        assert!(parse_args(&args(&["agent"])).is_err());
        assert!(parse_args(&args(&["--policy", "p"])).is_err());
        assert!(parse_args(&args(&["--policy"])).is_err());
        assert!(parse_args(&args(&["--verbose", "--policy", "p", "agent"])).is_err());
    }
}
