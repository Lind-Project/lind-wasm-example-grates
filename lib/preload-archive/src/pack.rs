//! Untrusted-side packer: read host files with `std::fs` and build an
//! archive. This is what `mkpreload` runs, and what an ocall handler would
//! run when an enclave asks for its preloads.

use std::fs;
use std::path::Path;

use crate::{ArchiveBuilder, parse_preload_entry};

/// What packing produced, plus one line per entry for a summary.
#[derive(Debug, Default)]
pub struct Packed {
    /// The finished archive, or None when no entry could be read.
    pub archive: Option<Vec<u8>>,
    /// `host -> imfs (n bytes)` for every entry that went in.
    pub staged: Vec<String>,
    /// One message per entry that was left out, and why.
    pub skipped: Vec<String>,
}

/// Read every valid entry from the host and pack it into one archive.
///
/// Each item of `entries` is `imfs_path=host_path` or a bare path, and may
/// itself be a colon-separated list of those (the `PRELOADS` format). Host
/// paths are resolved by the OS relative to the current directory. Every
/// file gets permission bits `mode`. Non-regular and unreadable files are
/// reported in `skipped` and the rest are still packed.
pub fn pack<S: AsRef<str>>(entries: &[S], mode: u32) -> Packed {
    let mut builder = ArchiveBuilder::new();
    let mut packed = Packed::default();

    for entry in entries.iter().flat_map(|e| e.as_ref().split(':')) {
        let (imfs_path, host_path) = match parse_preload_entry(entry) {
            Some(paths) => paths,
            None => continue,
        };

        let host = Path::new(host_path);
        match fs::metadata(host) {
            Ok(meta) if meta.is_file() => {}
            Ok(_) => {
                packed
                    .skipped
                    .push(format!("{}: not a regular file", host_path));
                continue;
            }
            Err(e) => {
                packed.skipped.push(format!("{}: {}", host_path, e));
                continue;
            }
        }

        match fs::read(host) {
            Ok(data) => {
                builder.push(imfs_path, mode, &data);
                packed.staged.push(format!(
                    "{} -> {} ({} bytes)",
                    host_path,
                    imfs_path,
                    data.len()
                ));
            }
            Err(e) => packed.skipped.push(format!("{}: {}", host_path, e)),
        }
    }

    if builder.entries() > 0 {
        packed.archive = Some(builder.finish());
    }
    packed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_archive;
    use std::path::PathBuf;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "preload-archive-test-{}-{}",
            std::process::id(),
            name
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
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
            pack(&["/nothing=/definitely/not/here"], 0o644)
                .archive
                .is_none()
        );
        let _ = fs::remove_dir_all(dir);
    }
}
