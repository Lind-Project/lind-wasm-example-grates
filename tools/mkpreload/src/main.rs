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
//! mkpreload [--mode OCTAL] <out> <entry>...
//! ```
//!
//! Each entry is `imfs_path=host_path` or a bare path used on both sides, the
//! same syntax as the IMFS grate's `PRELOADS`. An entry may itself be a
//! colon-separated list, so `mkpreload out "$PRELOADS"` works as-is. Every
//! file is given permission bits `--mode` (default 777, like `PRELOADS`).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use preload_archive::{ArchiveBuilder, parse_preload_entry};

const DEFAULT_MODE: u32 = 0o777;

struct Opts {
    out: PathBuf,
    mode: u32,
    entries: Vec<String>,
}

fn usage() -> String {
    "usage: mkpreload [--mode OCTAL] <out> <entry>...\n\
     \x20 entry: imfs_path=host_path | path, or a ':'-separated list of those"
        .to_string()
}

fn parse_args(args: &[String]) -> Result<Opts, String> {
    let mut mode = DEFAULT_MODE;
    let mut positional = Vec::new();
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--mode" => {
                let value = args.get(i + 1).ok_or("--mode needs an octal value")?;
                mode = u32::from_str_radix(value, 8)
                    .map_err(|_| format!("invalid --mode value: {}", value))?;
                i += 2;
            }
            "-h" | "--help" => return Err(usage()),
            other => {
                positional.push(other.to_string());
                i += 1;
            }
        }
    }

    if positional.len() < 2 {
        return Err(usage());
    }
    let out = PathBuf::from(positional.remove(0));
    Ok(Opts {
        out,
        mode,
        entries: positional,
    })
}

/// What packing produced, plus one line per entry for the summary.
struct Packed {
    archive: Option<Vec<u8>>,
    staged: Vec<String>,
    skipped: Vec<String>,
}

/// Read every valid entry from the host and pack it into one archive. Host
/// paths are resolved by the OS relative to the current directory.
fn pack(entries: &[String], mode: u32) -> Packed {
    let mut builder = ArchiveBuilder::new();
    let mut staged = Vec::new();
    let mut skipped = Vec::new();

    for entry in entries.iter().flat_map(|e| e.split(':')) {
        let (imfs_path, host_path) = match parse_preload_entry(entry) {
            Some(paths) => paths,
            None => continue,
        };

        let host = Path::new(host_path);
        match fs::metadata(host) {
            Ok(meta) if meta.is_file() => {}
            Ok(_) => {
                skipped.push(format!("{}: not a regular file", host_path));
                continue;
            }
            Err(e) => {
                skipped.push(format!("{}: {}", host_path, e));
                continue;
            }
        }

        match fs::read(host) {
            Ok(data) => {
                builder.push(imfs_path, mode, &data);
                staged.push(format!(
                    "{} -> {} ({} bytes)",
                    host_path,
                    imfs_path,
                    data.len()
                ));
            }
            Err(e) => skipped.push(format!("{}: {}", host_path, e)),
        }
    }

    Packed {
        archive: if builder.entries() > 0 {
            Some(builder.finish())
        } else {
            None
        },
        staged,
        skipped,
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let opts = match parse_args(&args) {
        Ok(opts) => opts,
        Err(msg) => {
            eprintln!("{}", msg);
            return ExitCode::FAILURE;
        }
    };

    let packed = pack(&opts.entries, opts.mode);
    for line in &packed.staged {
        eprintln!("packed: {}", line);
    }
    for line in &packed.skipped {
        eprintln!("skipped: {}", line);
    }

    let archive = match packed.archive {
        Some(archive) => archive,
        None => {
            eprintln!("mkpreload: nothing to pack");
            return ExitCode::FAILURE;
        }
    };

    if let Err(e) = fs::write(&opts.out, &archive) {
        eprintln!("mkpreload: cannot write {}: {}", opts.out.display(), e);
        return ExitCode::FAILURE;
    }
    eprintln!(
        "mkpreload: {} files, {} bytes -> {}",
        packed.staged.len(),
        archive.len(),
        opts.out.display()
    );
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;
    use preload_archive::parse_archive;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    /// A scratch directory unique to this test process.
    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("mkpreload-test-{}-{}", std::process::id(), name));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn args_take_an_output_path_then_entries() {
        let opts = parse_args(&args(&["out.mem", "/a=a.txt", "/b"])).unwrap();
        assert_eq!(opts.out, PathBuf::from("out.mem"));
        assert_eq!(opts.mode, 0o777);
        assert_eq!(opts.entries, args(&["/a=a.txt", "/b"]));

        let opts = parse_args(&args(&["--mode", "644", "out.mem", "/a"])).unwrap();
        assert_eq!(opts.mode, 0o644);

        assert!(parse_args(&args(&["out.mem"])).is_err());
        assert!(parse_args(&args(&["--mode", "9", "out.mem", "/a"])).is_err());
        assert!(parse_args(&args(&["--help"])).is_err());
    }

    #[test]
    fn packs_files_and_skips_what_it_cannot_read() {
        let dir = scratch("pack");
        fs::write(dir.join("a.txt"), b"alpha").unwrap();
        fs::write(dir.join("b.bin"), vec![7u8; 3000]).unwrap();
        fs::create_dir_all(dir.join("subdir")).unwrap();

        let d = dir.display();
        let list = format!("/a={d}/a.txt:sub/b={d}/b.bin::={d}/a.txt:{d}/subdir:{d}/missing");
        let packed = pack(&[list], 0o644);
        assert_eq!(packed.staged.len(), 2);
        assert_eq!(packed.skipped.len(), 2, "{:?}", packed.skipped);

        let archive = packed.archive.unwrap();
        let entries = parse_archive(&archive).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].path, "/a");
        assert_eq!(entries[0].mode, 0o644);
        assert_eq!(entries[0].data, b"alpha");
        assert_eq!(entries[1].path, "sub/b");
        assert_eq!(entries[1].data.len(), 3000);

        assert!(
            pack(&args(&["/nothing=/definitely/not/here"]), 0o644)
                .archive
                .is_none()
        );
        let _ = fs::remove_dir_all(dir);
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
        let packed = pack(&[list], DEFAULT_MODE);
        assert_eq!(packed.staged.len(), 5, "{:?}", packed.skipped);
        let expected = packed.archive.unwrap();

        if std::env::var_os("MKPRELOAD_REGEN_FIXTURE").is_some() {
            fs::write(&fixture, &expected).unwrap();
        }
        let on_disk = fs::read(&fixture)
            .expect("rust-grates/imfs-grate/test/preload_test.mem missing; run with MKPRELOAD_REGEN_FIXTURE=1");
        assert!(
            on_disk == expected,
            "preload_test.mem is stale; regenerate with MKPRELOAD_REGEN_FIXTURE=1 cargo test fixture"
        );
    }
}
