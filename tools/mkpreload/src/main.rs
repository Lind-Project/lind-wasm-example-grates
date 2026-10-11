//! mkpreload — pack host files into an IMFS preload archive.
//!
//! This is a plain native program; it does not run under Lind. It reads the
//! listed files and writes them as one contiguous preload archive (the format
//! in `lib/preload-archive`) to an output path. Point the output at a
//! memory-backed location that the Lind runtime can see, such as a tmpfs
//! directory under `lindfs` (`lindfs/dev/shm/...`), and the archive never
//! touches a disk. The IMFS grate then loads it with `--preload-file <path>`:
//! one read into its own memory, and the files are staged from that pointer.
//!
//! Usage:
//!
//! ```text
//! mkpreload [--mode OCTAL] [--print-digest] <out> <entry>... [--section <entry>...]...
//! mkpreload unpack <archive> [<root>]
//! ```
//!
//! Each entry is `imfs_path=host_path` or a bare path used on both sides, the
//! same syntax as the IMFS grate's `PRELOADS`. An entry may itself be a
//! colon-separated list, so `mkpreload out "$PRELOADS"` works as-is. Every
//! file is given permission bits `--mode` (default 777, like `PRELOADS`).
//!
//! `--section` starts another archive in the same output: the result is a
//! *bundle*, archives back to back, which the IMFS grate's `--preload-shm`
//! stages one archive at a time (for example the compiler pipeline, then the
//! source files, with an attestation after each). Without `--section` the
//! output is a single archive, as before.
//!
//! Each archive's SHA-256 digest is reported on stderr, and written to stdout
//! with `--print-digest` (one line per archive). Hand it to the consumer
//! through a trusted channel and it can refuse any other blob:
//! `imfs-grate --preload-digest`.
//!
//! `unpack` writes the files of an archive or bundle (for example the dump
//! archive of a run, see `imfs-grate --dump-shm`) under `root` (default `.`):
//! absolute entry paths are taken relative to `root`.
//!
//! The packing itself is `preload_archive::pack::pack`; this file is only the
//! command-line wrapper, so an ocall handler can reuse the same function.

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use preload_archive::pack::{pack_bundle, unpack};
use preload_archive::{digest_to_hex, read_header, split_bundle};

const DEFAULT_MODE: u32 = 0o777;

struct Opts {
    out: PathBuf,
    mode: u32,
    print_digest: bool,
    /// One list of entries per archive of the output.
    sections: Vec<Vec<String>>,
}

fn usage() -> String {
    "usage: mkpreload [--mode OCTAL] [--print-digest] <out> <entry>... [--section <entry>...]...\n\
     \x20      mkpreload unpack <archive> [<root>]\n\
     \x20 entry: imfs_path=host_path | path, or a ':'-separated list of those\n\
     \x20 --section: start another archive in the same output (a bundle)\n\
     \x20 --print-digest: write each archive's SHA-256 (hex) to stdout"
        .to_string()
}

fn parse_args(args: &[String]) -> Result<Opts, String> {
    let mut mode = DEFAULT_MODE;
    let mut print_digest = false;
    let mut positional = Vec::new();
    let mut sections: Vec<Vec<String>> = Vec::new();
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--mode" => {
                let value = args.get(i + 1).ok_or("--mode needs an octal value")?;
                mode = u32::from_str_radix(value, 8)
                    .map_err(|_| format!("invalid --mode value: {}", value))?;
                i += 2;
            }
            "--print-digest" => {
                print_digest = true;
                i += 1;
            }
            "--section" => {
                sections.push(Vec::new());
                i += 1;
            }
            "-h" | "--help" => return Err(usage()),
            other => {
                match sections.last_mut() {
                    Some(section) => section.push(other.to_string()),
                    None => positional.push(other.to_string()),
                }
                i += 1;
            }
        }
    }

    if positional.len() < 2 || sections.iter().any(|s| s.is_empty()) {
        return Err(usage());
    }
    let out = PathBuf::from(positional.remove(0));
    sections.insert(0, positional);
    Ok(Opts {
        out,
        mode,
        print_digest,
        sections,
    })
}

fn run_unpack(args: &[String]) -> ExitCode {
    let (archive, root) = match args {
        [archive] => (archive, "."),
        [archive, root] => (archive, root.as_str()),
        _ => {
            eprintln!("{}", usage());
            return ExitCode::FAILURE;
        }
    };
    let bytes = match fs::read(archive) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("mkpreload: cannot read {}: {}", archive, e);
            return ExitCode::FAILURE;
        }
    };
    match unpack(&bytes, std::path::Path::new(root)) {
        Ok(written) => {
            for path in &written {
                eprintln!("unpacked: {}", path);
            }
            eprintln!("mkpreload: {} files -> {}", written.len(), root);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("mkpreload: cannot unpack {}: {}", archive, e);
            ExitCode::FAILURE
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("unpack") {
        return run_unpack(&args[1..]);
    }
    let opts = match parse_args(&args) {
        Ok(opts) => opts,
        Err(msg) => {
            eprintln!("{}", msg);
            return ExitCode::FAILURE;
        }
    };

    let (bundle, reports) = pack_bundle(&opts.sections, opts.mode);
    let mut files = 0;
    for packed in &reports {
        for line in &packed.staged {
            eprintln!("packed: {}", line);
        }
        for line in &packed.skipped {
            eprintln!("skipped: {}", line);
        }
        files += packed.staged.len();
    }
    if files == 0 {
        eprintln!("mkpreload: nothing to pack");
        return ExitCode::FAILURE;
    }

    if let Err(e) = fs::write(&opts.out, &bundle) {
        eprintln!("mkpreload: cannot write {}: {}", opts.out.display(), e);
        return ExitCode::FAILURE;
    }

    eprintln!(
        "mkpreload: {} files, {} bytes -> {}",
        files,
        bundle.len(),
        opts.out.display()
    );
    let archives = split_bundle(&bundle).expect("freshly built bundle");
    for (i, archive) in archives.iter().enumerate() {
        let digest = digest_to_hex(&read_header(archive).expect("freshly built archive").digest);
        eprintln!(
            "mkpreload: archive {} ({} files, {} bytes) sha256 {}",
            i + 1,
            reports[i].staged.len(),
            archive.len(),
            digest
        );
        if opts.print_digest {
            println!("{}", digest);
        }
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn args_take_an_output_path_then_entries() {
        let opts = parse_args(&args(&["out.mem", "/a=a.txt", "/b"])).unwrap();
        assert_eq!(opts.out, PathBuf::from("out.mem"));
        assert_eq!(opts.mode, 0o777);
        assert!(!opts.print_digest);
        assert_eq!(opts.sections, vec![args(&["/a=a.txt", "/b"])]);

        let opts =
            parse_args(&args(&["--mode", "644", "--print-digest", "out.mem", "/a"])).unwrap();
        assert_eq!(opts.mode, 0o644);
        assert!(opts.print_digest);

        assert!(parse_args(&args(&["out.mem"])).is_err());
        assert!(parse_args(&args(&["--mode", "9", "out.mem", "/a"])).is_err());
        assert!(parse_args(&args(&["--help"])).is_err());
    }

    #[test]
    fn sections_split_the_entries_into_archives() {
        let opts = parse_args(&args(&[
            "out.mem",
            "/cc=cc",
            "--section",
            "/a.c=a.c",
            "/b.c",
            "--section",
            "/x",
        ]))
        .unwrap();
        assert_eq!(
            opts.sections,
            vec![
                args(&["/cc=cc"]),
                args(&["/a.c=a.c", "/b.c"]),
                args(&["/x"])
            ]
        );
        assert!(parse_args(&args(&["out.mem", "/a", "--section"])).is_err());
        assert!(parse_args(&args(&["out.mem", "--section", "/a"])).is_err());
    }

    /// The IMFS grate's `preload_test.c` runs once with `--preload-file` on a
    /// committed archive built from the same fixture files and the same list
    /// as its `PRELOADS` run (see test/grates_test.toml). This test pins that
    /// archive to this tool. Regenerate it with:
    ///
    ///   MKPRELOAD_REGEN_FIXTURE=1 cargo test fixture
    #[test]
    fn imfs_preload_fixture_matches_this_tool() {
        let test_dir =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rust-grates/imfs-grate/test");
        let fixture = test_dir.join("preload_test.mem");
        let host = |name: &str| test_dir.join(name).display().to_string();

        let list = format!(
            "/preload_hello.txt={h}:/preload/nested/data.txt={n}:sub/rel.txt={r}::={r}:{r}=:/trunc.txt={l}:/trunc.txt={s}",
            h = host("preload_hello.txt"),
            n = host("preload_nested.txt"),
            r = host("preload_rel.txt"),
            l = host("preload_long.txt"),
            s = host("preload_short.txt"),
        );
        let (expected, reports) = pack_bundle(&[vec![list]], DEFAULT_MODE);
        assert_eq!(reports[0].staged.len(), 5, "{:?}", reports[0].skipped);

        if std::env::var_os("MKPRELOAD_REGEN_FIXTURE").is_some() {
            fs::write(&fixture, &expected).unwrap();
        }
        let on_disk = fs::read(&fixture).expect(
            "rust-grates/imfs-grate/test/preload_test.mem missing; run with MKPRELOAD_REGEN_FIXTURE=1",
        );
        assert!(
            on_disk == expected,
            "preload_test.mem is stale; regenerate with MKPRELOAD_REGEN_FIXTURE=1 cargo test fixture"
        );
    }
}
