//! Untrusted-side packer: read host files with `std::fs` and build an
//! archive. This is what `mkpreload` runs, and what an ocall handler would
//! run when an enclave asks for its preloads.

use std::fs;
use std::path::Path;

use crate::{ArchiveBuilder, ArchiveError, parse_archive, parse_preload_entry, split_bundle};

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

/// Pack several lists into a bundle: one archive per list, back to back, in
/// order (for example the compiler pipeline, then the source files). Returns
/// the bundle and what happened to each list. A list from which no file
/// could be read still gets an (empty) archive, so that the position of each
/// archive in the bundle stays the position of its list.
pub fn pack_bundle<S: AsRef<str>>(sections: &[Vec<S>], mode: u32) -> (Vec<u8>, Vec<Packed>) {
    let mut bundle = Vec::new();
    let mut reports = Vec::new();
    for entries in sections {
        let mut packed = pack(entries, mode);
        let archive = packed
            .archive
            .take()
            .unwrap_or_else(|| ArchiveBuilder::new().finish());
        bundle.extend_from_slice(&archive);
        reports.push(packed);
    }
    (bundle, reports)
}

/// Write every file of a bundle (or a single archive) to the host. Absolute
/// entry paths are written under `root`, relative ones relative to it, so
/// `root` "/" restores absolute paths as they are. Missing parent
/// directories are created and existing files replaced. Returns the paths
/// written, in order.
pub fn unpack(bytes: &[u8], root: &Path) -> Result<Vec<String>, String> {
    let archives = split_bundle(bytes).map_err(|e: ArchiveError| e.to_string())?;
    let mut written = Vec::new();
    for archive in archives {
        for entry in parse_archive(archive).map_err(|e| e.to_string())? {
            let rel = entry.path.trim_start_matches('/');
            if rel.is_empty() || rel.split('/').any(|c| c == "..") {
                return Err(format!("refusing to unpack {:?}", entry.path));
            }
            let dest = root.join(rel);
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent).map_err(|e| format!("{}: {}", parent.display(), e))?;
            }
            fs::write(&dest, entry.data).map_err(|e| format!("{}: {}", dest.display(), e))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&dest, fs::Permissions::from_mode(entry.mode & 0o7777));
            }
            written.push(dest.display().to_string());
        }
    }
    Ok(written)
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

    #[test]
    fn bundles_pack_and_unpack() {
        let dir = scratch("bundle");
        fs::write(dir.join("cc"), b"compiler").unwrap();
        fs::write(dir.join("a.c"), b"int main(void) { return 0; }").unwrap();
        let d = dir.display();

        let (bundle, reports) = pack_bundle(
            &[
                vec![format!("/bin/cc={d}/cc")],
                vec![
                    format!("/src/a.c={d}/a.c"),
                    format!("/src/gone.c={d}/gone.c"),
                ],
                vec![format!("/none={d}/missing")],
            ],
            0o644,
        );
        assert_eq!(reports.len(), 3);
        assert_eq!(reports[1].staged.len(), 1);
        assert_eq!(reports[1].skipped.len(), 1);
        let archives = split_bundle(&bundle).unwrap();
        assert_eq!(archives.len(), 3);
        assert_eq!(parse_archive(archives[0]).unwrap()[0].path, "/bin/cc");
        assert!(parse_archive(archives[2]).unwrap().is_empty());

        let out = dir.join("out");
        let written = unpack(&bundle, &out).unwrap();
        assert_eq!(written.len(), 2);
        assert_eq!(fs::read(out.join("bin/cc")).unwrap(), b"compiler");
        assert_eq!(
            fs::read(out.join("src/a.c")).unwrap(),
            b"int main(void) { return 0; }"
        );

        let mut evil = ArchiveBuilder::new();
        evil.push("/../escape", 0o644, b"x");
        assert!(unpack(&evil.finish(), &out).is_err());
        let _ = fs::remove_dir_all(dir);
    }
}
