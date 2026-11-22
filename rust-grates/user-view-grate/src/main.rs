//! user-view-grate: per-user views of a file.
//!
//! A policy file names the files to protect and, for each, what every user sees of it: the lines
//! they may read (`keep` / `drop`), how those lines are rewritten on the way out (`replace`), and
//! whether what they write goes back into the real file (`write`). See `policy.rs` for the
//! format and the README for how the views are served.
//!
//! ```text
//! lind-wasm grates/user-view-grate.cwasm --policy views.conf [--user NAME] [--tmpdir DIR] -- program [args...]
//! ```

// On the build host only the unit tests use these modules; the handlers that call them are
// compiled for the grate alone.
#![cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]

mod fdtrack;
mod policy;
mod view;

#[cfg(target_arch = "wasm32")]
mod handlers;
#[cfg(target_arch = "wasm32")]
mod sys;

/// Command-line options, everything up to the program to run.
#[derive(Debug, Default, PartialEq, Eq)]
struct Options {
    policy: String,
    /// Treat every cage as this user. Without it a cage is identified by its effective uid.
    user: Option<String>,
    tmpdir: String,
    program: Vec<String>,
}

const USAGE: &str =
    "usage: user-view-grate --policy FILE [--user NAME] [--tmpdir DIR] [--] <program> [args...]";

fn parse_args(args: &[String]) -> Result<Options, String> {
    let mut opts = Options {
        tmpdir: "/tmp".into(),
        ..Default::default()
    };
    let mut i = 0;
    while i < args.len() {
        let flag = args[i].as_str();
        if flag == "--" {
            i += 1;
            break;
        }
        if !flag.starts_with("--") {
            break;
        }
        let value = args
            .get(i + 1)
            .cloned()
            .ok_or_else(|| format!("{flag} needs a value"));
        match flag {
            "--policy" => opts.policy = value?,
            "--user" => opts.user = Some(value?),
            "--tmpdir" => opts.tmpdir = value?,
            _ => return Err(format!("unknown option {flag}")),
        }
        i += 2;
    }
    opts.program = args[i..].to_vec();

    if opts.policy.is_empty() {
        return Err("--policy is required".into());
    }
    if opts.program.is_empty() {
        return Err("no program to run".into());
    }
    if !opts.tmpdir.starts_with('/') {
        return Err("--tmpdir must be an absolute path".into());
    }
    Ok(opts)
}

#[cfg(target_arch = "wasm32")]
fn main() {
    use grate_rs::constants::*;
    use grate_rs::{GrateBuilder, GrateError};

    let args: Vec<String> = std::env::args().skip(1).collect();
    let opts = match parse_args(&args) {
        Ok(opts) => opts,
        Err(e) => {
            eprintln!("user-view-grate: {e}\n{USAGE}");
            std::process::exit(2);
        }
    };

    let text = match sys::read_file(&opts.policy) {
        Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        Err(errno) => {
            eprintln!(
                "user-view-grate: cannot read policy {}: errno {}",
                opts.policy, -errno
            );
            std::process::exit(2);
        }
    };
    let policy = match policy::Policy::parse(&text) {
        Ok(policy) => policy,
        Err(e) => {
            eprintln!("user-view-grate: {}: {e}", opts.policy);
            std::process::exit(2);
        }
    };
    // Found out now, not at the first open of a protected file.
    if let Err(errno) = sys::ensure_dir(&opts.tmpdir) {
        eprintln!(
            "user-view-grate: --tmpdir {}: not a directory that can be used: errno {}",
            opts.tmpdir, -errno
        );
        std::process::exit(2);
    }
    let fixed_user = opts.user.as_deref().map(|n| policy.identity_for_name(n));
    handlers::init(policy, fixed_user, opts.tmpdir);

    GrateBuilder::new()
        .register(SYS_OPEN, handlers::open_handler)
        .register(SYS_OPENAT, handlers::openat_handler)
        .register(SYS_CLOSE, handlers::close_handler)
        .register(SYS_FSYNC, handlers::fsync_handler)
        .register(SYS_FDATASYNC, handlers::fdatasync_handler)
        .register(SYS_DUP, handlers::dup_handler)
        .register(SYS_DUP2, handlers::dup2_handler)
        .register(SYS_DUP3, handlers::dup3_handler)
        .register(SYS_FCNTL, handlers::fcntl_handler)
        .register(SYS_CLONE, handlers::clone_handler)
        .register(SYS_EXECVE, handlers::execve_handler)
        .register(SYS_EXIT, handlers::exit_handler)
        .register(SYS_EXIT_GROUP, handlers::exit_group_handler)
        .register(SYS_TRUNCATE, handlers::truncate_handler)
        .register(SYS_UNLINK, handlers::unlink_handler)
        .register(SYS_UNLINKAT, handlers::unlinkat_handler)
        .register(SYS_RENAME, handlers::rename_handler)
        .register(SYS_RENAMEAT, handlers::renameat_handler)
        .register(SYS_RENAMEAT2, handlers::renameat2_handler)
        .teardown(|result: Result<i32, GrateError>| {
            // Views still open when the last cage went away without exiting cleanly.
            handlers::commit_all();
            if let Err(e) = result {
                eprintln!("user-view-grate: {e:?}");
            }
        })
        .run(opts.program);
}

#[cfg(not(target_arch = "wasm32"))]
fn main() {
    // Built for the host only to run the unit tests of the policy, view and fd-tracking modules.
    let args: Vec<String> = std::env::args().skip(1).collect();
    match parse_args(&args) {
        Ok(_) => eprintln!("user-view-grate runs only as a lind-wasm grate"),
        Err(e) => eprintln!("user-view-grate: {e}\n{USAGE}"),
    }
    std::process::exit(2);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    #[test]
    fn options_then_program() {
        let o = parse_args(&args("--policy p.conf --user alice -- prog.cwasm -x --policy")).unwrap();
        assert_eq!(o.policy, "p.conf");
        assert_eq!(o.user.as_deref(), Some("alice"));
        assert_eq!(o.tmpdir, "/tmp");
        assert_eq!(o.program, args("prog.cwasm -x --policy"));

        // `--` is optional: the first word that is not an option starts the program.
        let o = parse_args(&args("--policy p.conf --tmpdir /scratch prog.cwasm --user bob")).unwrap();
        assert_eq!(o.user, None);
        assert_eq!(o.tmpdir, "/scratch");
        assert_eq!(o.program, args("prog.cwasm --user bob"));
    }

    #[test]
    fn bad_command_lines() {
        for (line, want) in [
            ("prog.cwasm", "--policy is required"),
            ("--policy p.conf", "no program"),
            ("--policy p.conf --", "no program"),
            ("--policy", "needs a value"),
            ("--policy p.conf --frob prog", "unknown option"),
            ("--policy p.conf --tmpdir rel prog", "absolute"),
        ] {
            let err = parse_args(&args(line)).unwrap_err();
            assert!(err.contains(want), "{line:?}: {err}");
        }
    }
}
