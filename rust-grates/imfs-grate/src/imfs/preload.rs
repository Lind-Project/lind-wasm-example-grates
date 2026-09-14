//! Staging a preload archive into IMFS.
//!
//! The archive (see the `preload-archive` crate) is one contiguous block of
//! memory holding every file to stage. Whoever built it, IMFS receives it as
//! a `(pointer, size)` pair and builds its nodes straight from those bytes:
//!
//! - IMFS itself never touches the host filesystem.
//! - Files are created directly in the node/chunk arenas, not through the
//!   POSIX layer, so no fd table, `open()`, or `write()` is involved.
//! - Each directory prefix is resolved once and cached; staging a file does
//!   not walk the tree from `/` again for every path component.

use std::collections::HashMap;

use preload_archive::{ArchiveError, parse_archive};

use super::ImfsState;
use super::node::*;

/// What a preload brought into IMFS. Per-entry problems (a path that
/// collides with a directory, for example) are not errors: the entry is
/// skipped and counted here.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PreloadStats {
    pub staged: usize,
    pub skipped: usize,
    pub bytes: usize,
}

impl ImfsState {
    /// Stage every entry of a preload archive into the filesystem.
    ///
    /// Paths are interpreted like PRELOADS entries: absolute paths from `/`,
    /// relative paths against cage 0's cwd. Missing parent directories are
    /// created. An existing regular file at an entry's path is truncated and
    /// rewritten; an entry whose path (or one of its parents) is taken by a
    /// non-directory, or whose final component is a directory, is skipped.
    ///
    /// A malformed archive is rejected as a whole before any node is created.
    pub fn preload_archive(&mut self, bytes: &[u8]) -> Result<PreloadStats, ArchiveError> {
        let entries = parse_archive(bytes)?;
        let mut stats = PreloadStats::default();

        // Directory cache: normalized absolute path -> directory node index.
        // A prefix is resolved (or created) once, no matter how many entries
        // live under it.
        let mut dirs: HashMap<String, usize> = HashMap::new();
        dirs.insert("/".to_string(), self.root_idx);

        for entry in entries {
            let norm_path = self.normalize_path_for_cage(0, entry.path);
            match self.stage_file(&mut dirs, &norm_path, entry.mode, entry.data) {
                Ok(()) => {
                    stats.staged += 1;
                    stats.bytes += entry.data.len();
                }
                Err(reason) => {
                    crate::log!("preload: skipping {}: {}", entry.path, reason);
                    stats.skipped += 1;
                }
            }
        }

        Ok(stats)
    }

    /// Create or rewrite one regular file directly in the arenas.
    fn stage_file(
        &mut self,
        dirs: &mut HashMap<String, usize>,
        norm_path: &str,
        mode: u32,
        data: &[u8],
    ) -> Result<(), &'static str> {
        let components: Vec<&str> = norm_path.split('/').filter(|s| !s.is_empty()).collect();
        let (name, parents) = match components.split_last() {
            Some(split) => split,
            None => return Err("path names the root directory"),
        };
        if name.len() >= MAX_NODE_NAME {
            return Err("file name too long");
        }

        let parent_idx = self.ensure_dirs(dirs, parents)?;

        let node_idx = match self.lookup_child(parent_idx, name) {
            Some(existing) => {
                let existing = self.follow_hardlinks(existing);
                if self.nodes[existing].node_type != NodeType::Reg {
                    return Err("path exists and is not a regular file");
                }
                self.truncate_node(existing, 0);
                self.nodes[existing].mode = 0o100000 | (mode & 0o7777);
                existing
            }
            None => {
                let idx = self.create_node(name, NodeType::Reg, mode);
                self.add_child(parent_idx, idx);
                self.update_mtime(parent_idx);
                self.update_ctime(parent_idx);
                idx
            }
        };

        // write_to_node allocates the chunk chain straight from the archive
        // bytes; no fd or offset bookkeeping is involved.
        let written = self.write_to_node(node_idx, 0, data);
        if written != data.len() {
            return Err("short write into IMFS");
        }
        self.update_mtime(node_idx);
        self.update_ctime(node_idx);
        Ok(())
    }

    /// Return the node index of the directory `/a/b/c` for components
    /// `["a", "b", "c"]`, creating missing levels. Every resolved level is
    /// cached so later entries under the same prefix cost one map lookup.
    fn ensure_dirs(
        &mut self,
        dirs: &mut HashMap<String, usize>,
        components: &[&str],
    ) -> Result<usize, &'static str> {
        let mut path = String::from("/");
        let mut current = self.root_idx;

        for (depth, component) in components.iter().enumerate() {
            if depth > 0 {
                path.push('/');
            }
            path.push_str(component);

            if let Some(&idx) = dirs.get(&path) {
                current = idx;
                continue;
            }

            current = match self.lookup_child(current, component) {
                Some(existing) => {
                    let existing = self.follow_hardlinks(existing);
                    if self.nodes[existing].node_type != NodeType::Dir {
                        return Err("parent path exists and is not a directory");
                    }
                    existing
                }
                None => {
                    if component.len() >= MAX_NODE_NAME {
                        return Err("directory name too long");
                    }
                    self.create_dir_node(current, component, 0o755)
                }
            };
            dirs.insert(path.clone(), current);
        }

        Ok(current)
    }

    fn follow_hardlinks(&self, mut idx: usize) -> usize {
        while let NodeInfo::HardLink { target } = &self.nodes[idx].info {
            idx = *target;
        }
        idx
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use grate_rs::constants::fs::O_RDONLY;
    use preload_archive::ArchiveBuilder;

    const CAGE: u64 = 0;

    fn ensure_cage() {
        if !fdtables::check_cage_exists(CAGE) {
            fdtables::init_empty_cage(CAGE);
        }
    }

    /// Read a file back through the normal POSIX layer, so the test checks
    /// what a cage would see rather than the arena directly.
    fn cat(state: &mut ImfsState, path: &str) -> Result<Vec<u8>, i32> {
        ensure_cage();
        let fd = state.open(CAGE, path, O_RDONLY, 0);
        if fd < 0 {
            return Err(fd);
        }
        let mut out = Vec::new();
        let mut buf = [0u8; 700];
        loop {
            let n = state.read(CAGE, fd as u64, &mut buf);
            assert!(n >= 0);
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n as usize]);
        }
        assert_eq!(state.close(CAGE, fd as u64), 0);
        Ok(out)
    }

    fn mode_of(state: &mut ImfsState, path: &str) -> u32 {
        let mut st = grate_rs::ffi::stat::default();
        assert_eq!(state.stat(CAGE, path, &mut st), 0, "stat {}", path);
        st.st_mode
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| ((i * 7 + 3) & 0xff) as u8).collect()
    }

    fn archive(entries: &[(&str, u32, &[u8])]) -> Vec<u8> {
        let mut b = ArchiveBuilder::new();
        for (path, mode, data) in entries {
            b.push(path, *mode, data);
        }
        b.finish()
    }

    #[test]
    fn stages_files_and_creates_parent_dirs() {
        let mut state = ImfsState::new();
        let bytes = archive(&[
            ("/hello.txt", 0o777, b"hello from the host\n"),
            ("/preload/nested/data.txt", 0o644, b"nested payload\n"),
            ("/preload/nested/big.bin", 0o644, &pattern(3000)),
            ("/preload/exact.bin", 0o644, &pattern(2048)),
            ("/preload/empty", 0o644, b""),
        ]);

        let stats = state.preload_archive(&bytes).unwrap();
        assert_eq!(
            stats,
            PreloadStats {
                staged: 5,
                skipped: 0,
                bytes: 20 + 15 + 3000 + 2048
            }
        );

        assert_eq!(
            cat(&mut state, "/hello.txt").unwrap(),
            b"hello from the host\n"
        );
        assert_eq!(
            cat(&mut state, "/preload/nested/data.txt").unwrap(),
            b"nested payload\n"
        );
        assert_eq!(
            cat(&mut state, "/preload/nested/big.bin").unwrap(),
            pattern(3000)
        );
        assert_eq!(
            cat(&mut state, "/preload/exact.bin").unwrap(),
            pattern(2048)
        );
        assert_eq!(cat(&mut state, "/preload/empty").unwrap(), b"");

        assert_eq!(mode_of(&mut state, "/preload") & 0o170000, 0o040000);
        assert_eq!(mode_of(&mut state, "/preload/nested"), 0o040755);
        assert_eq!(mode_of(&mut state, "/hello.txt"), 0o100777);
        assert_eq!(mode_of(&mut state, "/preload/nested/data.txt"), 0o100644);

        // Created directories have working . and .. entries.
        assert_eq!(
            cat(&mut state, "/preload/nested/../nested/./data.txt").unwrap(),
            b"nested payload\n"
        );
        // 1 + 1 + 3 + 2 chunks; the empty file has none.
        assert_eq!(state.chunks.len(), 7);
    }

    #[test]
    fn relative_paths_resolve_against_cage_zero_cwd() {
        let mut state = ImfsState::new();
        let bytes = archive(&[("sub/rel.txt", 0o644, b"relative payload\n")]);
        assert_eq!(state.preload_archive(&bytes).unwrap().staged, 1);
        assert_eq!(
            cat(&mut state, "/sub/rel.txt").unwrap(),
            b"relative payload\n"
        );
        assert_eq!(mode_of(&mut state, "/sub") & 0o170000, 0o040000);
    }

    #[test]
    fn restaging_a_path_keeps_only_the_last_contents() {
        let mut state = ImfsState::new();
        let bytes = archive(&[
            ("/trunc.txt", 0o644, &pattern(2500)),
            ("/trunc.txt", 0o600, b"short"),
        ]);
        let stats = state.preload_archive(&bytes).unwrap();
        assert_eq!(stats.staged, 2);
        assert_eq!(cat(&mut state, "/trunc.txt").unwrap(), b"short");
        assert_eq!(mode_of(&mut state, "/trunc.txt"), 0o100600);
        // The first version's chunks were reclaimed, not leaked.
        assert_eq!(state.chunks.len() - state.chunk_free_list.len(), 1);

        // A second archive later on rewrites the file too.
        let again = archive(&[("/trunc.txt", 0o644, b"again")]);
        assert_eq!(state.preload_archive(&again).unwrap().staged, 1);
        assert_eq!(cat(&mut state, "/trunc.txt").unwrap(), b"again");
    }

    #[test]
    fn existing_directories_are_reused_not_replaced() {
        let mut state = ImfsState::new();
        assert_eq!(state.mkdir(CAGE, "/existing", 0o700), 0);
        let bytes = archive(&[
            ("/existing/a", 0o644, b"a"),
            ("/existing/deeper/b", 0o644, b"b"),
        ]);
        assert_eq!(state.preload_archive(&bytes).unwrap().staged, 2);
        assert_eq!(mode_of(&mut state, "/existing"), 0o040700);
        assert_eq!(cat(&mut state, "/existing/a").unwrap(), b"a");
        assert_eq!(cat(&mut state, "/existing/deeper/b").unwrap(), b"b");
    }

    #[test]
    fn conflicting_entries_are_skipped_without_dropping_the_rest() {
        let mut state = ImfsState::new();
        assert_eq!(state.mkdir(CAGE, "/dir", 0o755), 0);
        let bytes = archive(&[
            ("/dir", 0o644, b"a directory is in the way"),
            ("/file", 0o644, b"file"),
            ("/file/child", 0o644, b"parent is a file"),
            ("/", 0o644, b"root"),
            ("/ok", 0o644, b"ok"),
        ]);
        let stats = state.preload_archive(&bytes).unwrap();
        assert_eq!(stats.staged, 2);
        assert_eq!(stats.skipped, 3);
        assert_eq!(mode_of(&mut state, "/dir") & 0o170000, 0o040000);
        assert_eq!(cat(&mut state, "/file").unwrap(), b"file");
        assert_eq!(cat(&mut state, "/ok").unwrap(), b"ok");
    }

    #[test]
    fn empty_archive_stages_nothing() {
        let mut state = ImfsState::new();
        let stats = state
            .preload_archive(&ArchiveBuilder::new().finish())
            .unwrap();
        assert_eq!(stats, PreloadStats::default());
        assert_eq!(state.nodes.len(), 3);
    }

    #[test]
    fn a_corrupt_archive_leaves_the_filesystem_untouched() {
        let mut bad = archive(&[("/a", 0o644, b"abc")]);
        bad.push(0);
        let mut state = ImfsState::new();
        assert_eq!(
            state.preload_archive(&bad),
            Err(ArchiveError::TrailingBytes(1))
        );
        assert_eq!(state.nodes.len(), 3);
        assert_eq!(cat(&mut state, "/a"), Err(-2));
    }
}
