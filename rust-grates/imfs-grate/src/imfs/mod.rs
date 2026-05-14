//! In-Memory Filesystem (IMFS).
//!
//! The filesystem is a tree of Nodes stored in an arena-style Vec.
//! File data is stored in chains of 1024-byte Chunks.
//!
//! fd management is handled entirely by the fdtables library:
//!   - underfd  = node index (which file this fd points to)
//!
//! The only per-fd state we track ourselves is the read/write offset,
//! stored in a HashMap<(cage_id, fd), offset>.

pub mod node;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use grate_rs::ffi::stat;
use node::*;

use grate_rs::constants::fs::*;

/// fdtables fdkind for IMFS file descriptors.
pub const IMFS_FDKIND: u32 = 1;
const IMFS_F_GETFD: i32 = 1;
const IMFS_F_SETFD: i32 = 2;
const IMFS_FD_CLOEXEC: i32 = 1;

/// Global IMFS state.
pub static IMFS: Mutex<Option<ImfsState>> = Mutex::new(None);

/// Access the global IMFS state. Panics if not initialized.
pub fn with_imfs<F, R>(f: F) -> R
where
    F: FnOnce(&mut ImfsState) -> R,
{
    let mut guard = IMFS.lock().unwrap();
    f(guard.as_mut().expect("IMFS not initialized"))
}

pub struct FDInfo {
    flags: u64,
    offset: i64,
}

/// Lind-compatible statfs data layout.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct FsData {
    pub f_type: u64,
    pub f_bsize: u64,
    pub f_blocks: u64,
    pub f_bfree: u64,
    pub f_bavail: u64,
    pub f_files: u64,
    pub f_ffiles: u64,
    pub f_fsid: u64,
    pub f_namelen: u64,
    pub f_frsize: u64,
    pub f_spare: [u8; 32],
}

const DIRENT64_FIXED_SIZE: usize = 8 + 8 + 2 + 1;
const IMFS_BLOCK_SIZE: i32 = 512;
const LIND_AT_FDCWD: i32 = -100;
const IMFS_STATFS_MAGIC: u64 = 0x494d_4653; // "IMFS"
const IMFS_STATFS_BLOCK_SIZE: u64 = 4096;
const IMFS_STATFS_TOTAL_BLOCKS: u64 = 1024 * 1024;
const IMFS_STATFS_NAME_MAX: u64 = 254;
const S_IFMT: u32 = 0o170000;
const S_IFIFO: u32 = 0o010000;
const S_IFREG: u32 = 0o100000;

/// The complete IMFS state.
pub struct ImfsState {
    pub nodes: Vec<Node>,
    pub chunks: Vec<Chunk>,
    node_free_list: Vec<usize>,
    chunk_free_list: Vec<usize>,
    pub root_idx: usize,

    /// Per-fd read/write offsets: (cage_id, fd) -> offset.
    /// This is the ONLY per-fd state we track outside of fdtables.
    /// fdtables stores everything else (node index as underfd, flags as perfdinfo).
    // pub offsets: HashMap<(u64, u64), i64>,
    pub fd_info: HashMap<(u64, u64), Arc<Mutex<FDInfo>>>,

    /// List of current working directories for each cage.
    pub cwd_info: HashMap<u64, String>,
}

/// Initialize the global IMFS. Called once at startup.
pub fn init() {
    let mut state = ImfsState {
        nodes: Vec::with_capacity(MAX_NODES),
        chunks: Vec::new(),
        node_free_list: Vec::new(),
        chunk_free_list: Vec::new(),
        root_idx: 0,
        fd_info: HashMap::new(),
        cwd_info: HashMap::new(),
    };

    state.cwd_info.insert(0, "/".to_string());

    // Create root directory.
    let root_idx = state.create_node("/", NodeType::Dir, 0o755);
    state.nodes[root_idx].parent_idx = root_idx;
    state.root_idx = root_idx;

    // Create . and .. in root.
    let dot_idx = state.create_node(".", NodeType::Lnk, 0);
    state.nodes[dot_idx].info = NodeInfo::HardLink { target: root_idx };
    state.add_child(root_idx, dot_idx);

    let dotdot_idx = state.create_node("..", NodeType::Lnk, 0);
    state.nodes[dotdot_idx].info = NodeInfo::HardLink { target: root_idx };
    state.add_child(root_idx, dotdot_idx);

    *IMFS.lock().unwrap() = Some(state);
}

impl ImfsState {
    // =====================================================================
    //  Timestamp helpers
    // =====================================================================

    fn update_atime(&mut self, node_idx: usize) {
        self.nodes[node_idx].atime = NodeTime::now();
    }

    fn update_mtime(&mut self, node_idx: usize) {
        self.nodes[node_idx].mtime = NodeTime::now();
    }

    fn update_ctime(&mut self, node_idx: usize) {
        self.nodes[node_idx].ctime = NodeTime::now();
    }

    // =====================================================================
    //  Directory read helpers
    // =====================================================================

    fn dirent_type(&self, node_idx: usize) -> u8 {
        let mut idx = node_idx;

        while let NodeInfo::HardLink { target } = &self.nodes[idx].info {
            idx = *target;
        }

        match self.nodes[idx].node_type {
            NodeType::Dir => DT_DIR,
            NodeType::Reg => DT_REG,
            NodeType::Lnk => DT_LNK,
            NodeType::Pip => DT_FIFO,
            _ => DT_UNKNOWN,
        }
    }

    fn dirent_reclen(name_len: usize) -> usize {
        let reclen = DIRENT64_FIXED_SIZE + name_len + 1;
        (reclen + 7) & !7
    }

    fn write_dirent_record(
        buf: &mut [u8],
        ino: u64,
        next_offset: u64,
        d_type: u8,
        name: &str,
    ) -> usize {
        let reclen = Self::dirent_reclen(name.len());
        let record = &mut buf[..reclen];

        record.fill(0);
        record[0..8].copy_from_slice(&ino.to_ne_bytes());
        record[8..16].copy_from_slice(&next_offset.to_ne_bytes());
        record[16..18].copy_from_slice(&(reclen as u16).to_ne_bytes());
        record[18] = d_type;

        let name_start = DIRENT64_FIXED_SIZE;
        let name_end = name_start + name.len();
        record[name_start..name_end].copy_from_slice(name.as_bytes());

        reclen
    }

    // =====================================================================
    //  Node management
    // =====================================================================

    /// Allocate a new node. Reuses slots from the free list if available,
    /// otherwise appends to the nodes Vec. Returns the node's index.
    fn create_node(&mut self, name: &str, node_type: NodeType, mode: u32) -> usize {
        if let Some(free_idx) = self.node_free_list.pop() {
            self.nodes[free_idx] = Node::new(free_idx, name, node_type, mode);
            free_idx
        } else {
            let idx = self.nodes.len();
            self.nodes.push(Node::new(idx, name, node_type, mode));
            idx
        }
    }

    /// Add a child node to a directory. Updates the child's parent_idx.
    fn add_child(&mut self, parent_idx: usize, child_idx: usize) {
        let child_name = self.nodes[child_idx].name.clone();
        self.nodes[parent_idx].children_mut().push(DirEntry {
            name: child_name,
            node_idx: child_idx,
        });
        self.nodes[child_idx].parent_idx = parent_idx;
    }

    /// Remove a child from its parent directory's children list.
    fn remove_child(&mut self, node_idx: usize) {
        let parent_idx = self.nodes[node_idx].parent_idx;
        let name = self.nodes[node_idx].name.clone();
        self.nodes[parent_idx]
            .children_mut()
            .retain(|e| e.name != name);
    }

    /// Mark a node slot as free and return it to the free list for reuse.
    fn reclaim_node(&mut self, idx: usize) {
        let chunk_head = match &mut self.nodes[idx].info {
            NodeInfo::Reg { head, tail } => {
                let old_head = *head;
                *head = None;
                *tail = None;
                old_head
            }
            _ => None,
        };
        self.reclaim_chunk_chain(chunk_head);

        self.nodes[idx].node_type = NodeType::Free;
        self.nodes[idx].info = NodeInfo::Free;
        self.node_free_list.push(idx);
    }

    fn link_count(&self, node_idx: usize) -> u32 {
        match &self.nodes[node_idx].info {
            NodeInfo::Dir { children } => {
                let child_dirs = children
                    .iter()
                    .filter(|entry| entry.name != "." && entry.name != "..")
                    .filter(|entry| self.nodes[entry.node_idx].node_type == NodeType::Dir)
                    .count() as u32;
                2 + child_dirs
            }
            _ => self
                .nodes
                .iter()
                .filter_map(|node| match &node.info {
                    NodeInfo::Dir { children } => Some(children),
                    _ => None,
                })
                .flat_map(|children| children.iter())
                .filter(|entry| {
                    entry.node_idx == node_idx
                        || matches!(
                            &self.nodes[entry.node_idx].info,
                            NodeInfo::HardLink { target } if *target == node_idx
                        )
                })
                .count() as u32,
        }
    }

    fn unlink_node(&mut self, node_idx: usize) {
        if let NodeInfo::HardLink { target } = &self.nodes[node_idx].info {
            let target = *target;
            self.update_ctime(target);
            if self.link_count(target) == 0 {
                self.nodes[target].doomed = true;
                if self.nodes[target].in_use == 0 {
                    self.reclaim_node(target);
                }
            }
            self.reclaim_node(node_idx);
            return;
        }

        if self.link_count(node_idx) == 0 {
            self.nodes[node_idx].doomed = true;
            if self.nodes[node_idx].in_use == 0 {
                self.reclaim_node(node_idx);
            }
        }
    }

    // =====================================================================
    //  Chunk management
    // =====================================================================

    /// Allocate a new empty chunk. Reuses from free list or appends.
    /// Returns the chunk index in self.chunks.
    fn alloc_chunk(&mut self) -> usize {
        if let Some(free_idx) = self.chunk_free_list.pop() {
            self.chunks[free_idx] = Chunk::new();
            free_idx
        } else {
            let idx = self.chunks.len();
            self.chunks.push(Chunk::new());
            idx
        }
    }

    fn reclaim_chunk(&mut self, idx: usize) {
        self.chunks[idx] = Chunk::new();
        self.chunk_free_list.push(idx);
    }

    fn reclaim_chunk_chain(&mut self, mut chunk_idx: Option<usize>) {
        while let Some(ci) = chunk_idx {
            let next = self.chunks[ci].next;
            self.reclaim_chunk(ci);
            chunk_idx = next;
        }
    }

    // =====================================================================
    //  Path resolution
    // =====================================================================

    fn normalize_path_for_cage(&self, cage_id: u64, path: &str) -> String {
        let base = if path.starts_with('/') {
            "/".to_string()
        } else {
            self.cwd_info
                .get(&cage_id)
                .cloned()
                .unwrap_or_else(|| "/".to_string())
        };

        let mut parts: Vec<&str> = Vec::new();

        for part in base.split('/').chain(path.split('/')) {
            match part {
                "" | "." => {}
                ".." => {
                    parts.pop();
                }
                x => parts.push(x),
            }
        }

        if parts.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", parts.join("/"))
        }
    }

    fn normalize_path_from_base(base: &str, path: &str) -> String {
        let base = if path.starts_with('/') { "/" } else { base };
        let mut parts: Vec<&str> = Vec::new();

        for part in base.split('/').chain(path.split('/')) {
            match part {
                "" | "." => {}
                ".." => {
                    parts.pop();
                }
                x => parts.push(x),
            }
        }

        if parts.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", parts.join("/"))
        }
    }

    fn lookup_child(&self, parent_idx: usize, name: &str) -> Option<usize> {
        self.nodes[parent_idx]
            .children()
            .iter()
            .find(|entry| entry.name == name)
            .map(|entry| entry.node_idx)
    }

    /// Walk the node tree to find the node at the given absolute path.
    /// Returns ENOENT if a component is missing, ENOTDIR if an intermediate
    /// component is not a directory. If follow_final is false, the last path
    /// component is returned without following a link node.
    fn resolve_path(&self, path: &str, follow_final: bool) -> Result<usize, i32> {
        self.resolve_path_inner(path, follow_final, 0)
    }

    fn resolve_path_inner(
        &self,
        path: &str,
        follow_final: bool,
        depth: usize,
    ) -> Result<usize, i32> {
        if depth > 40 {
            return Err(-40); // ELOOP
        }

        if path == "/" {
            return Ok(self.root_idx);
        }

        let components: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if components.is_empty() {
            return Ok(self.root_idx);
        }

        let mut current = self.root_idx;

        for (idx, component) in components.iter().enumerate() {
            if self.nodes[current].node_type != NodeType::Dir {
                return Err(-20); // ENOTDIR
            }

            let entry_idx = self.lookup_child(current, component).ok_or(-2)?; // ENOENT
            let is_final = idx + 1 == components.len();

            current = if is_final && !follow_final {
                entry_idx
            } else if let Some(target) = self.nodes[entry_idx].hardlink_target() {
                target
            } else if let Some(target) = self.nodes[entry_idx].symlink_target() {
                let parent_path = self.absolute_path_for_node(current);
                let mut resolved = Self::normalize_path_from_base(&parent_path, target);
                let remaining = &components[idx + 1..];
                if !remaining.is_empty() {
                    resolved = Self::normalize_path_from_base(&resolved, &remaining.join("/"));
                }
                return self.resolve_path_inner(&resolved, follow_final, depth + 1);
            } else {
                entry_idx
            };
        }

        Ok(current)
    }

    /// Split a path into its parent directory and final filename.
    /// Returns ENOENT if a parent component is missing, ENOTDIR if an
    /// intermediate component is not a directory.
    fn resolve_parent_and_name(&self, path: &str) -> Result<(usize, String), i32> {
        let components: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if components.is_empty() {
            return Err(-2); // ENOENT
        }

        let filename = components.last().unwrap().to_string();

        if components.len() == 1 {
            return Ok((self.root_idx, filename));
        }

        let parent_path = format!("/{}", components[..components.len() - 1].join("/"));
        let parent_idx = self.resolve_path(&parent_path, true)?;
        if self.nodes[parent_idx].node_type != NodeType::Dir {
            return Err(-20); // ENOTDIR
        }

        Ok((parent_idx, filename))
    }

    fn absolute_path_for_node(&self, node_idx: usize) -> String {
        if node_idx == self.root_idx {
            return "/".to_string();
        }

        let mut parts = Vec::new();
        let mut current = node_idx;

        while current != self.root_idx {
            parts.push(self.nodes[current].name.clone());
            current = self.nodes[current].parent_idx;
        }

        parts.reverse();
        format!("/{}", parts.join("/"))
    }

    fn normalize_path_at(&self, cage_id: u64, dirfd: i32, path: &str) -> Result<String, i32> {
        if path.starts_with('/') {
            return Ok(self.normalize_path_for_cage(cage_id, path));
        }

        if dirfd == LIND_AT_FDCWD {
            return Ok(self.normalize_path_for_cage(cage_id, path));
        }

        let entry = match fdtables::translate_virtual_fd(cage_id, dirfd as u64) {
            Ok(entry) => entry,
            Err(_) => return Err(-9), // EBADF
        };

        let mut node_idx = entry.underfd as usize;
        while let NodeInfo::HardLink { target } = &self.nodes[node_idx].info {
            node_idx = *target;
        }

        if self.nodes[node_idx].node_type != NodeType::Dir {
            return Err(-20); // ENOTDIR
        }

        let base = self.absolute_path_for_node(node_idx);
        Ok(self.normalize_path_for_cage(cage_id, &format!("{}/{}", base, path)))
    }

    // =====================================================================
    //  FD and metadata helpers
    // =====================================================================

    fn fill_stat(&self, node_idx: usize, statbuf: &mut stat) {
        let node = &self.nodes[node_idx];

        *statbuf = stat {
            st_dev: 1,
            st_ino: node_idx as u64,
            st_mode: node.mode,
            st_nlink: self.link_count(node_idx),
            st_uid: 0, //node.owner,
            st_gid: 0, //node.group,
            st_rdev: 0,
            st_size: node.total_size as u64,
            st_blksize: IMFS_BLOCK_SIZE,
            st_blocks: (node.total_size / IMFS_BLOCK_SIZE as usize) as u32,
            st_atim: node.atime.as_stat_pair(),
            st_mtim: node.mtime.as_stat_pair(),
            st_ctim: node.ctime.as_stat_pair(),
        };
    }

    fn fill_statfs(&self, statbuf: &mut FsData) {
        let used_bytes: u64 = self.nodes.iter().map(|node| node.total_size as u64).sum();
        let used_blocks = used_bytes.div_ceil(IMFS_STATFS_BLOCK_SIZE);
        let free_blocks = IMFS_STATFS_TOTAL_BLOCKS.saturating_sub(used_blocks);
        let free_nodes =
            (MAX_NODES.saturating_sub(self.nodes.len()) + self.node_free_list.len()) as u64;

        *statbuf = FsData {
            f_type: IMFS_STATFS_MAGIC,
            f_bsize: IMFS_STATFS_BLOCK_SIZE,
            f_blocks: IMFS_STATFS_TOTAL_BLOCKS,
            f_bfree: free_blocks,
            f_bavail: free_blocks,
            f_files: MAX_NODES as u64,
            f_ffiles: free_nodes,
            f_fsid: 0,
            f_namelen: IMFS_STATFS_NAME_MAX,
            f_frsize: IMFS_STATFS_BLOCK_SIZE,
            f_spare: [0; 32],
        };
    }

    fn open_resolved_path(&mut self, cage_id: u64, norm_path: &str, flags: i32, mode: u32) -> i32 {
        let node_idx = if let Ok(idx) = self.resolve_path(norm_path, true) {
            if (flags & O_EXCL) != 0 && (flags & O_CREAT) != 0 {
                return -17; // EEXIST
            }
            if (flags & O_DIRECTORY) != 0 && self.nodes[idx].node_type != NodeType::Dir {
                return -20; // ENOTDIR
            }
            if self.nodes[idx].node_type == NodeType::Dir {
                match flags & O_ACCMODE {
                    O_WRONLY | O_RDWR => return -21, // EISDIR
                    _ => {}
                }
            }

            // Check permissions.
            let m = self.nodes[idx].mode;
            match flags & O_ACCMODE {
                O_RDONLY if m & S_IRUSR == 0 => return -13,
                O_WRONLY if m & S_IWUSR == 0 => return -13,
                O_RDWR if m & S_IRUSR == 0 || m & S_IWUSR == 0 => return -13,
                _ => {}
            }

            if self.nodes[idx].node_type == NodeType::Reg
                && (flags & O_TRUNC) != 0
                && (flags & O_ACCMODE) != O_RDONLY
            {
                self.truncate_node(idx, 0);
                self.update_mtime(idx);
                self.update_ctime(idx);
            }

            idx
        } else {
            if (flags & O_CREAT) == 0 {
                return -2; // ENOENT
            }
            let (parent_idx, filename) = match self.resolve_parent_and_name(norm_path) {
                Ok(p) => p,
                Err(e) => return e,
            };
            if filename.len() >= MAX_NODE_NAME {
                return -36; // ENAMETOOLONG
            }
            let new_idx = self.create_node(&filename, NodeType::Reg, mode);
            self.add_child(parent_idx, new_idx);
            self.update_mtime(parent_idx);
            self.update_ctime(parent_idx);
            self.update_mtime(new_idx);
            self.update_ctime(new_idx);
            new_idx
        };

        self.nodes[node_idx].in_use += 1;

        match fdtables::get_unused_virtual_fd(cage_id, IMFS_FDKIND, node_idx as u64, false, 0) {
            Ok(vfd) => {
                let new_fdinfo = Arc::new(Mutex::new(FDInfo {
                    flags: flags as u64,
                    offset: 0,
                }));

                self.fd_info.insert((cage_id, vfd), new_fdinfo.clone());

                vfd as i32
            }
            Err(_) => {
                self.nodes[node_idx].in_use -= 1;
                -24 // EMFILE
            }
        }
    }

    fn get_offset(&self, cageid: u64, fd: u64) -> i64 {
        let underfd = self.fd_info.get(&(cageid, fd)).unwrap().lock().unwrap();

        underfd.offset
    }

    fn set_offset(&self, cageid: u64, fd: u64, offset: i64) {
        let mut underfd = self.fd_info.get(&(cageid, fd)).unwrap().lock().unwrap();

        underfd.offset = offset;
    }

    // =====================================================================
    //  Internal chunk read/write
    // =====================================================================

    /// Read bytes from a regular file's chunk chain starting at the given byte offset.
    /// Walks the linked list of chunks, skipping past the offset, then copies data
    /// into buf. Returns the number of bytes actually read (may be less than buf.len()
    /// if EOF is reached).
    fn read_from_node(&self, node_idx: usize, offset: usize, buf: &mut [u8]) -> usize {
        let node = &self.nodes[node_idx];
        if offset >= node.total_size {
            return 0;
        }

        let count = buf.len().min(node.total_size - offset);
        let head = match &node.info {
            NodeInfo::Reg { head, .. } => *head,
            _ => return 0,
        };

        let mut chunk_idx = head;
        let mut local_offset = offset;

        // Skip chunks before the read offset.
        while let Some(ci) = chunk_idx {
            if local_offset < CHUNK_SIZE {
                break;
            }
            local_offset -= CHUNK_SIZE;
            chunk_idx = self.chunks[ci].next;
        }

        let mut read = 0;
        while read < count {
            let ci = match chunk_idx {
                Some(ci) => ci,
                None => break,
            };
            let available = self.chunks[ci].used.saturating_sub(local_offset);
            let to_copy = (count - read).min(available);
            buf[read..read + to_copy]
                .copy_from_slice(&self.chunks[ci].data[local_offset..local_offset + to_copy]);
            read += to_copy;
            local_offset = 0;
            chunk_idx = self.chunks[ci].next;
        }

        read
    }

    /// Write bytes to a regular file's chunk chain starting at the given byte offset.
    /// Allocates new chunks as needed when writing past the end. Zero-fills any holes
    /// between the chunk's current used size and the write offset. Updates the node's
    /// total_size if the write extends the file. Returns the number of bytes written.
    fn write_to_node(&mut self, node_idx: usize, offset: usize, buf: &[u8]) -> usize {
        if buf.is_empty() {
            return 0;
        }

        let mut chunk_idx = match &self.nodes[node_idx].info {
            NodeInfo::Reg { head, .. } => *head,
            _ => return 0,
        };

        let mut local_offset = offset;

        // Skip to the chunk containing the write offset.
        while let Some(ci) = chunk_idx {
            if local_offset < CHUNK_SIZE {
                break;
            }
            self.chunks[ci].used = CHUNK_SIZE;
            local_offset -= CHUNK_SIZE;
            chunk_idx = self.chunks[ci].next;
        }

        let mut written = 0;

        while written < buf.len() {
            let ci = match chunk_idx {
                Some(ci) => ci,
                None => {
                    // Allocate a new chunk and link it.
                    let new_ci = self.alloc_chunk();
                    match &mut self.nodes[node_idx].info {
                        NodeInfo::Reg { head, tail } => {
                            if let Some(t) = *tail {
                                self.chunks[t].next = Some(new_ci);
                            }
                            if head.is_none() {
                                *head = Some(new_ci);
                            }
                            *tail = Some(new_ci);
                        }
                        _ => return written,
                    }
                    new_ci
                }
            };

            if local_offset >= CHUNK_SIZE {
                self.chunks[ci].used = CHUNK_SIZE;
                local_offset -= CHUNK_SIZE;
                chunk_idx = self.chunks[ci].next;
                continue;
            }

            let space = CHUNK_SIZE - local_offset;
            let to_copy = (buf.len() - written).min(space);

            // Zero-fill holes.
            let used = self.chunks[ci].used;
            if local_offset > used {
                self.chunks[ci].data[used..local_offset].fill(0);
            }

            self.chunks[ci].data[local_offset..local_offset + to_copy]
                .copy_from_slice(&buf[written..written + to_copy]);

            if local_offset + to_copy > self.chunks[ci].used {
                self.chunks[ci].used = local_offset + to_copy;
            }

            written += to_copy;
            local_offset = 0;
            chunk_idx = self.chunks[ci].next;
        }

        if offset + written > self.nodes[node_idx].total_size {
            self.nodes[node_idx].total_size = offset + written;
        }

        written
    }

    fn truncate_node(&mut self, node_idx: usize, new_size: usize) {
        let old_size = self.nodes[node_idx].total_size;

        if new_size == old_size {
            return;
        }

        if new_size > old_size {
            let zero = [0u8; 1];
            let _ = self.write_to_node(node_idx, new_size - 1, &zero);
            return;
        }

        if new_size == 0 {
            let head = match &mut self.nodes[node_idx].info {
                NodeInfo::Reg { head, tail } => {
                    let old_head = *head;
                    *head = None;
                    *tail = None;
                    old_head
                }
                _ => return,
            };

            self.reclaim_chunk_chain(head);
            self.nodes[node_idx].total_size = 0;
            return;
        }

        let mut remaining = new_size;
        let mut current = match &self.nodes[node_idx].info {
            NodeInfo::Reg { head, .. } => *head,
            _ => return,
        };

        let mut last_keep = None;

        while let Some(ci) = current {
            if remaining > CHUNK_SIZE {
                remaining -= CHUNK_SIZE;
                last_keep = Some(ci);
                current = self.chunks[ci].next;
                continue;
            }

            self.chunks[ci].used = remaining;
            let to_reclaim = self.chunks[ci].next;
            self.chunks[ci].next = None;
            self.reclaim_chunk_chain(to_reclaim);

            if let NodeInfo::Reg { tail, .. } = &mut self.nodes[node_idx].info {
                *tail = Some(ci);
            }

            self.nodes[node_idx].total_size = new_size;
            return;
        }

        if let Some(ci) = last_keep {
            self.chunks[ci].next = None;
            if let NodeInfo::Reg { tail, .. } = &mut self.nodes[node_idx].info {
                *tail = Some(ci);
            }
        }

        self.nodes[node_idx].total_size = new_size;
    }

    // =====================================================================
    //  FD resolution helpers
    // =====================================================================

    // Helper function to get the node_idx and flag for a give cageid and fd.
    // In case the node_idx points to a Lnk, it follows the link until we hit a real Node.
    fn get_node_and_flags(&mut self, cage_id: u64, fd: u64) -> Result<(usize, i32), i32> {
        let entry = match fdtables::translate_virtual_fd(cage_id, fd) {
            Ok(e) => e,
            Err(_) => return Err(-9),
        };

        let node_idx = entry.underfd as usize;

        let fd_info = self.fd_info.get(&(cage_id, fd)).unwrap().lock().unwrap();
        let flags = fd_info.flags as i32;

        let mut idx = node_idx;

        // If the node is a Link, follow until we hit an actual Node.
        // Streamlines process of reading/writing symlink'd files.
        while let NodeInfo::HardLink { target } = &self.nodes[idx].info {
            idx = *target;
        }

        return Ok((idx as usize, flags));
    }

    pub fn insert_perfdinfo(&mut self, cageid: u64, fd: u64, flags: u64) {
        self.fd_info.insert(
            (cageid, fd),
            Arc::new(Mutex::new(FDInfo {
                flags: flags,
                offset: 0,
            })),
        );
    }

    pub fn dup(&mut self, cage_id: u64, oldfd: u64) -> i32 {
        let entry = match fdtables::translate_virtual_fd(cage_id, oldfd) {
            Ok(entry) => entry,
            Err(_) => return -9,
        };

        let fd_info = match self.fd_info.get(&(cage_id, oldfd)).cloned() {
            Some(info) => info,
            None => return -9,
        };

        let node_idx = entry.underfd as usize;
        if node_idx >= self.nodes.len() {
            return -9;
        }

        if let NodeInfo::Pip {
            readers, writers, ..
        } = &mut self.nodes[node_idx].info
        {
            let flags = fd_info.lock().unwrap().flags as i32;
            match flags & O_ACCMODE {
                O_WRONLY => *writers += 1,
                _ => *readers += 1,
            }
        }

        match fdtables::get_unused_virtual_fd(cage_id, IMFS_FDKIND, entry.underfd, false, 0) {
            Ok(newfd) => {
                self.nodes[node_idx].in_use += 1;
                self.fd_info.insert((cage_id, newfd), fd_info);
                newfd as i32
            }
            Err(_) => -24,
        }
    }

    pub fn dup2(&mut self, cage_id: u64, oldfd: u64, newfd: u64, cloexec: bool) -> i32 {
        let entry = match fdtables::translate_virtual_fd(cage_id, oldfd) {
            Ok(entry) => entry,
            Err(_) => return -9,
        };

        let fd_info = match self.fd_info.get(&(cage_id, oldfd)).cloned() {
            Some(info) => info,
            None => return -9,
        };

        if oldfd == newfd {
            return newfd as i32;
        }

        let node_idx = entry.underfd as usize;
        if node_idx >= self.nodes.len() {
            return -9;
        }

        if fdtables::translate_virtual_fd(cage_id, newfd).is_ok() {
            let close_ret = self.close(cage_id, newfd);
            if close_ret != 0 {
                return close_ret;
            }
        }

        match fdtables::get_specific_virtual_fd(
            cage_id,
            newfd,
            IMFS_FDKIND,
            entry.underfd,
            cloexec,
            0,
        ) {
            Ok(_) => {
                self.nodes[node_idx].in_use += 1;
                if let NodeInfo::Pip {
                    readers, writers, ..
                } = &mut self.nodes[node_idx].info
                {
                    let flags = fd_info.lock().unwrap().flags as i32;
                    match flags & O_ACCMODE {
                        O_WRONLY => *writers += 1,
                        _ => *readers += 1,
                    }
                }
                self.fd_info.insert((cage_id, newfd), fd_info);
                newfd as i32
            }
            Err(_) => -24,
        }
    }

    fn dup_from_startfd(&mut self, cage_id: u64, oldfd: u64, startfd: i32, cloexec: bool) -> i32 {
        if startfd < 0 {
            return -22;
        }

        let entry = match fdtables::translate_virtual_fd(cage_id, oldfd) {
            Ok(entry) => entry,
            Err(_) => return -9,
        };

        let fd_info = match self.fd_info.get(&(cage_id, oldfd)).cloned() {
            Some(info) => info,
            None => return -9,
        };

        let node_idx = entry.underfd as usize;
        if node_idx >= self.nodes.len() {
            return -9;
        }

        match fdtables::get_unused_virtual_fd_from_startfd(
            cage_id,
            IMFS_FDKIND,
            entry.underfd,
            cloexec,
            0,
            startfd as u64,
        ) {
            Ok(newfd) => {
                self.nodes[node_idx].in_use += 1;
                if let NodeInfo::Pip {
                    readers, writers, ..
                } = &mut self.nodes[node_idx].info
                {
                    let flags = fd_info.lock().unwrap().flags as i32;
                    match flags & O_ACCMODE {
                        O_WRONLY => *writers += 1,
                        _ => *readers += 1,
                    }
                }
                self.fd_info.insert((cage_id, newfd), fd_info);
                newfd as i32
            }
            Err(_) => -24,
        }
    }

    // =====================================================================
    //  Public filesystem operations
    //
    //  These use fdtables directly:
    //    - underfd  = node index
    //    - offsets HashMap for per-fd read/write position
    // =====================================================================

    /// fork: shares the FDInfo information to the child cage.
    pub fn fork(&mut self, parent_cage: u64, child_cage: u64) {
        for ((cage_id, fd), underfd_arc) in self.fd_info.clone().iter() {
            if *cage_id == parent_cage {
                self.fd_info.insert((child_cage, *fd), underfd_arc.clone());
            }
        }

        if let Some(cwd) = self.cwd_info.get(&parent_cage).cloned() {
            self.cwd_info.insert(child_cage, cwd);
        }
    }

    /// chdir
    pub fn chdir(&mut self, cage_id: u64, path: &str) -> i32 {
        let norm_path = self.normalize_path_for_cage(cage_id, path);
        let node_idx = match self.resolve_path(&norm_path, true) {
            Ok(idx) => idx,
            Err(e) => return e,
        };

        if self.nodes[node_idx].node_type != NodeType::Dir {
            return -20; // ENOTDIR
        }

        self.cwd_info.insert(cage_id, norm_path);
        0
    }

    /// fchdir: change current working directory using an open directory fd.
    pub fn fchdir(&mut self, cage_id: u64, fd: u64) -> i32 {
        let entry = match fdtables::translate_virtual_fd(cage_id, fd) {
            Ok(entry) => entry,
            Err(_) => return -9, // EBADF
        };

        let mut node_idx = entry.underfd as usize;

        if node_idx >= self.nodes.len() {
            return -9; // EBADF
        }

        // Follow link nodes until reaching the actual target.
        while let NodeInfo::HardLink { target } = &self.nodes[node_idx].info {
            node_idx = *target;

            if node_idx >= self.nodes.len() {
                return -9; // EBADF
            }
        }

        if self.nodes[node_idx].node_type != NodeType::Dir {
            return -20; // ENOTDIR
        }

        let cwd = self.absolute_path_for_node(node_idx);
        self.cwd_info.insert(cage_id, cwd);

        0
    }

    pub fn getcwd(&self, cage_id: u64) -> Result<String, i32> {
        self.cwd_info.get(&cage_id).cloned().ok_or(-1)
    }

    pub fn access(&mut self, cage_id: u64, path: &str, mode: i32) -> i32 {
        let norm_path = self.normalize_path_for_cage(cage_id, path);
        self.access_resolved_path(&norm_path, mode)
    }

    pub fn accessat(&mut self, cage_id: u64, dirfd: i32, path: &str, mode: i32) -> i32 {
        let norm_path = match self.normalize_path_at(cage_id, dirfd, path) {
            Ok(path) => path,
            Err(e) => return e,
        };
        self.access_resolved_path(&norm_path, mode)
    }

    fn access_resolved_path(&mut self, norm_path: &str, mode: i32) -> i32 {
        let node_idx = match self.resolve_path(&norm_path, true) {
            Ok(idx) => idx,
            Err(e) => return e,
        };

        if mode == F_OK {
            return if node_idx < self.nodes.len() { 0 } else { -2 };
        }

        let m = self.nodes[node_idx].mode;
        if (mode & R_OK) != 0 && (m & S_IRUSR) == 0 {
            return -13; // EACCES
        }
        if (mode & W_OK) != 0 && (m & S_IWUSR) == 0 {
            return -13; // EACCES
        }
        if (mode & X_OK) != 0 && (m & S_IXUSR) == 0 {
            return -13; // EACCES
        }

        0
    }

    /// xstat
    pub fn stat(&mut self, cage_id: u64, path: &str, statbuf: &mut stat) -> i32 {
        let norm_path = self.normalize_path_for_cage(cage_id, path);
        self.stat_resolved_path(&norm_path, statbuf, true)
    }

    pub fn lstat(&mut self, cage_id: u64, path: &str, statbuf: &mut stat) -> i32 {
        let norm_path = self.normalize_path_for_cage(cage_id, path);
        self.stat_resolved_path(&norm_path, statbuf, false)
    }

    pub fn statfs(&mut self, cage_id: u64, path: &str, statbuf: &mut FsData) -> i32 {
        let norm_path = self.normalize_path_for_cage(cage_id, path);
        match self.resolve_path(&norm_path, true) {
            Ok(_) => {
                self.fill_statfs(statbuf);
                0
            }
            Err(e) => e,
        }
    }

    pub fn statat(
        &mut self,
        cage_id: u64,
        dirfd: i32,
        path: &str,
        statbuf: &mut stat,
        flags: i32,
    ) -> i32 {
        let supported_flags =
            libc::AT_SYMLINK_NOFOLLOW | libc::AT_NO_AUTOMOUNT | libc::AT_EMPTY_PATH;
        if flags & !supported_flags != 0 {
            return -22; // EINVAL
        }

        if path.is_empty() && flags & libc::AT_EMPTY_PATH != 0 {
            let node_idx = if dirfd == LIND_AT_FDCWD {
                let norm_path = self.normalize_path_for_cage(cage_id, ".");
                match self.resolve_path(&norm_path, true) {
                    Ok(idx) => idx,
                    Err(e) => return e,
                }
            } else {
                let entry = match fdtables::translate_virtual_fd(cage_id, dirfd as u64) {
                    Ok(entry) => entry,
                    Err(_) => return -9, // EBADF
                };
                entry.underfd as usize
            };

            if node_idx >= self.nodes.len() {
                return -9; // EBADF
            }
            self.fill_stat(node_idx, statbuf);
            self.update_atime(node_idx);
            return 0;
        }

        let norm_path = match self.normalize_path_at(cage_id, dirfd, path) {
            Ok(path) => path,
            Err(e) => return e,
        };
        self.stat_resolved_path(&norm_path, statbuf, flags & libc::AT_SYMLINK_NOFOLLOW == 0)
    }

    fn stat_resolved_path(
        &mut self,
        norm_path: &str,
        statbuf: &mut stat,
        follow_final: bool,
    ) -> i32 {
        let node_idx = match self.resolve_path(&norm_path, follow_final) {
            Ok(idx) => idx,
            Err(e) => return e,
        };

        self.fill_stat(node_idx, statbuf);

        0
    }

    /// fxstat
    pub fn fstat(&mut self, cage_id: u64, fd: u64, statbuf: &mut stat) -> i32 {
        let (node_idx, _) = match self.get_node_and_flags(cage_id, fd) {
            Ok((n, f)) => (n, f),
            Err(e) => return e,
        };

        self.fill_stat(node_idx, statbuf);

        0
    }

    pub fn fstatfs(&mut self, cage_id: u64, fd: u64, statbuf: &mut FsData) -> i32 {
        if let Err(e) = self.get_node_and_flags(cage_id, fd) {
            return e;
        }

        self.fill_statfs(statbuf);
        0
    }

    /// rmdir: remove an empty directory.
    pub fn rmdir(&mut self, cage_id: u64, path: &str) -> i32 {
        let norm_path = self.normalize_path_for_cage(cage_id, path);
        self.rmdir_resolved_path(&norm_path)
    }

    fn rmdir_resolved_path(&mut self, norm_path: &str) -> i32 {
        let node_idx = match self.resolve_path(&norm_path, true) {
            Ok(idx) => idx,
            Err(e) => return e,
        };

        if node_idx == self.root_idx {
            return -16; // EBUSY
        }

        let children = match &self.nodes[node_idx].info {
            NodeInfo::Dir { children } => children,
            _ => return -20, // ENOTDIR
        };

        if children
            .iter()
            .any(|entry| entry.name != "." && entry.name != "..")
        {
            return -39; // ENOTEMPTY
        }

        let parent_idx = self.nodes[node_idx].parent_idx;
        self.remove_child(node_idx);
        self.update_mtime(parent_idx);
        self.update_ctime(parent_idx);
        self.update_ctime(node_idx);
        self.unlink_node(node_idx);

        0
    }

    /// open: create or open a file. Returns the fd allocated by fdtables.
    pub fn open(&mut self, cage_id: u64, path: &str, flags: i32, mode: u32) -> i32 {
        let norm_path = self.normalize_path_for_cage(cage_id, path);
        self.open_resolved_path(cage_id, &norm_path, flags, mode)
    }

    pub fn openat(&mut self, cage_id: u64, dirfd: i32, path: &str, flags: i32, mode: u32) -> i32 {
        let norm_path = match self.normalize_path_at(cage_id, dirfd, path) {
            Ok(path) => path,
            Err(e) => return e,
        };
        self.open_resolved_path(cage_id, &norm_path, flags, mode)
    }

    /// close: close an fd via fdtables and clean up the offset.
    pub fn close(&mut self, cage_id: u64, fd: u64) -> i32 {
        // Look up the node before closing so we can decrement in_use.
        if let Ok(entry) = fdtables::translate_virtual_fd(cage_id, fd) {
            let node_idx = entry.underfd as usize;
            if node_idx < self.nodes.len() {
                self.nodes[node_idx].in_use = self.nodes[node_idx].in_use.saturating_sub(1);
                if self.nodes[node_idx].doomed && self.nodes[node_idx].in_use == 0 {
                    self.reclaim_node(node_idx);
                }
            }
        }

        // Remove our offset tracking.
        self.fd_info.remove(&(cage_id, fd));

        // Close in fdtables.
        match fdtables::close_virtualfd(cage_id, fd) {
            Ok(_) => 0,
            Err(_) => -9, // EBADF
        }
    }

    /// read: read from a file at the current offset.
    pub fn read(&mut self, cage_id: u64, fd: u64, buf: &mut [u8]) -> i32 {
        // Look up fd in fdtables — get node index and flags.
        let (node_idx, flags) = match self.get_node_and_flags(cage_id, fd) {
            Ok((n, f)) => (n, f),
            Err(e) => return e,
        };

        match &self.nodes[node_idx].info {
            NodeInfo::Reg { head: _, tail: _ } => {}
            _ => return -9,
        };

        if (flags & O_ACCMODE) == O_WRONLY {
            return -9;
        }

        // Get the current offset from our tracking.
        let offset = self.get_offset(cage_id, fd);

        let n = self.read_from_node(node_idx, offset as usize, buf);
        if n > 0 {
            self.update_atime(node_idx);
        }

        // Advance the offset.
        self.set_offset(cage_id, fd, offset + n as i64);

        n as i32
    }

    /// pread: read at a specific offset without changing the fd offset.
    pub fn pread(&mut self, cage_id: u64, fd: u64, buf: &mut [u8], offset: i64) -> i32 {
        if offset < 0 {
            return -22; // EINVAL
        }

        // Look up fd in fdtables — get node index and flags.
        let (node_idx, flags) = match self.get_node_and_flags(cage_id, fd) {
            Ok((n, f)) => (n, f),
            Err(e) => return e,
        };

        // Return EBADF for reads on non regular files.
        // TODO: Implement pipe reads.
        match &self.nodes[node_idx].info {
            NodeInfo::Reg { head: _, tail: _ } => {}
            _ => return -9,
        };

        if (flags & O_ACCMODE) == O_WRONLY {
            return -9;
        }

        let n = self.read_from_node(node_idx, offset as usize, buf);
        if n > 0 {
            self.update_atime(node_idx);
        }

        n as i32
    }

    /// write: write to a file at the current offset.
    pub fn write(&mut self, cage_id: u64, fd: u64, buf: &[u8]) -> i32 {
        let (node_idx, flags) = match self.get_node_and_flags(cage_id, fd) {
            Ok((n, f)) => (n, f),
            Err(e) => return e,
        };

        match &self.nodes[node_idx].info {
            NodeInfo::Reg { head: _, tail: _ } => {}
            _ => return -9,
        };

        if (flags & O_ACCMODE) == O_RDONLY {
            return -9;
        }

        let offset = if (flags & O_APPEND) != 0 {
            self.nodes[node_idx].total_size as i64
        } else {
            self.get_offset(cage_id, fd)
        };

        let n = self.write_to_node(node_idx, offset as usize, buf);
        if n > 0 {
            self.update_mtime(node_idx);
            self.update_ctime(node_idx);
        }

        self.set_offset(cage_id, fd, offset + n as i64);

        n as i32
    }

    /// pwrite: write at a specific offset without changing the fd offset.
    pub fn pwrite(&mut self, cage_id: u64, fd: u64, buf: &[u8], offset: i64) -> i32 {
        if offset < 0 {
            return -22; // EINVAL
        }

        // Look up fd in fdtables — get node index and flags.
        let (node_idx, flags) = match self.get_node_and_flags(cage_id, fd) {
            Ok((n, f)) => (n, f),
            Err(e) => return e,
        };

        // Return EBADF for writes on non regular files.
        // TODO: Implement pipe reads.
        match &self.nodes[node_idx].info {
            NodeInfo::Reg { head: _, tail: _ } => {}
            _ => return -9,
        };

        if (flags & O_ACCMODE) == O_RDONLY {
            return -9;
        }

        let n = self.write_to_node(node_idx, offset as usize, buf);
        if n > 0 {
            self.update_mtime(node_idx);
            self.update_ctime(node_idx);
        }

        n as i32
    }

    /// lseek: reposition the fd offset.
    pub fn lseek(&mut self, cage_id: u64, fd: u64, offset: i64, whence: i32) -> i32 {
        let (node_idx, _) = match self.get_node_and_flags(cage_id, fd) {
            Ok((n, f)) => (n, f),
            Err(e) => return e,
        };

        // Only valid for regular files,
        match &self.nodes[node_idx].info {
            NodeInfo::Reg { .. } => {}
            NodeInfo::Pip { .. } => return -29, // EISPIPE
            NodeInfo::Dir { .. } => return offset as i32, // On directory lseeks, we return offset
            // immediately.
            _ => return -9, // EBADF on Free/Lnk (will never be hit)
        };

        let current = self.get_offset(cage_id, fd);

        let new_offset = match whence {
            SEEK_SET => offset,
            SEEK_CUR => current + offset,
            SEEK_END => self.nodes[node_idx].total_size as i64 + offset,
            _ => return -22,
        };

        if new_offset < 0 {
            return -22;
        }

        self.set_offset(cage_id, fd, new_offset);

        new_offset as i32
    }

    /// fcntl: only F_GETFL implemented — returns flags from fdtables perfdinfo.
    pub fn fcntl(&mut self, cage_id: u64, fd: u64, op: i32, arg: i32) -> i32 {
        match op {
            F_DUPFD => self.dup_from_startfd(cage_id, fd, arg, false),
            F_DUPFD_CLOEXEC => self.dup_from_startfd(cage_id, fd, arg, true),
            IMFS_F_GETFD => match fdtables::translate_virtual_fd(cage_id, fd) {
                Ok(entry) => {
                    if entry.should_cloexec {
                        IMFS_FD_CLOEXEC
                    } else {
                        0
                    }
                }
                Err(_) => -9,
            },
            IMFS_F_SETFD => match fdtables::set_cloexec(cage_id, fd, arg & IMFS_FD_CLOEXEC != 0) {
                Ok(_) => 0,
                Err(_) => -9,
            },
            F_GETFL => {
                let Some(fd_info) = self.fd_info.get(&(cage_id, fd)) else {
                    return -9;
                };
                let fd_info = fd_info.lock().unwrap();

                fd_info.flags as i32
            }
            _ => -1,
        }
    }

    /// getdents: serialize directory entries into Linux dirent records.
    pub fn getdents(&mut self, cage_id: u64, fd: u64, buf: &mut [u8]) -> i32 {
        let (node_idx, flags) = match self.get_node_and_flags(cage_id, fd) {
            Ok((n, f)) => (n, f),
            Err(e) => return e,
        };

        match &self.nodes[node_idx].info {
            NodeInfo::Dir { .. } => {}
            _ => return -20, // ENOTDIR
        }

        if (flags & O_ACCMODE) == O_WRONLY {
            return -9; // EBADF
        }

        let start = self.get_offset(cage_id, fd);
        if start < 0 {
            return -22; // EINVAL
        }

        let children = match &self.nodes[node_idx].info {
            NodeInfo::Dir { children } => children.clone(),
            _ => unreachable!(),
        };

        let mut entry_idx = start as usize;
        let mut written = 0usize;

        while entry_idx < children.len() {
            let entry = &children[entry_idx];
            let reclen = Self::dirent_reclen(entry.name.len());

            if reclen > buf.len() {
                return -22; // EINVAL
            }
            if written + reclen > buf.len() {
                break;
            }

            let next_offset = (entry_idx + 1) as u64;
            let d_type = self.dirent_type(entry.node_idx);
            let ino = (entry.node_idx as u64) + 1;

            written += Self::write_dirent_record(
                &mut buf[written..written + reclen],
                ino,
                next_offset,
                d_type,
                &entry.name,
            );
            entry_idx += 1;
        }

        self.set_offset(cage_id, fd, entry_idx as i64);

        written as i32
    }

    /// unlink: remove a non-directory path entry.
    pub fn unlink(&mut self, cage_id: u64, path: &str) -> i32 {
        let norm_path = self.normalize_path_for_cage(cage_id, path);
        self.unlink_resolved_path(&norm_path)
    }

    pub fn unlinkat(&mut self, cage_id: u64, dirfd: i32, path: &str, flags: i32) -> i32 {
        let supported_flags = libc::AT_REMOVEDIR;
        if flags & !supported_flags != 0 {
            return -22; // EINVAL
        }

        let norm_path = match self.normalize_path_at(cage_id, dirfd, path) {
            Ok(path) => path,
            Err(e) => return e,
        };

        if flags & libc::AT_REMOVEDIR != 0 {
            self.rmdir_resolved_path(&norm_path)
        } else {
            self.unlink_resolved_path(&norm_path)
        }
    }

    fn unlink_resolved_path(&mut self, norm_path: &str) -> i32 {
        if norm_path == "/" {
            return -1; // EPERM
        }

        let (parent_idx, filename) = match self.resolve_parent_and_name(&norm_path) {
            Ok(parts) => parts,
            Err(e) => return e,
        };

        if filename == "." || filename == ".." {
            return -1; // EPERM
        }

        let node_idx = match self.resolve_path(&norm_path, false) {
            Ok(idx) => idx,
            Err(e) => return e,
        };

        if self.nodes[node_idx].node_type == NodeType::Dir {
            return -21; // EISDIR
        };

        self.remove_child(node_idx);
        self.update_mtime(parent_idx);
        self.update_ctime(parent_idx);
        self.update_ctime(node_idx);
        self.unlink_node(node_idx);

        0
    }

    pub fn link(&mut self, cage_id: u64, oldpath: &str, newpath: &str) -> i32 {
        let norm_oldpath = self.normalize_path_for_cage(cage_id, oldpath);
        let norm_newpath = self.normalize_path_for_cage(cage_id, newpath);
        self.link_resolved_paths(&norm_oldpath, &norm_newpath, true)
    }

    pub fn linkat(
        &mut self,
        cage_id: u64,
        olddirfd: i32,
        oldpath: &str,
        newdirfd: i32,
        newpath: &str,
        flags: i32,
    ) -> i32 {
        let supported_flags = libc::AT_SYMLINK_FOLLOW;
        if flags & !supported_flags != 0 {
            return -22; // EINVAL
        }

        let norm_oldpath = match self.normalize_path_at(cage_id, olddirfd, oldpath) {
            Ok(path) => path,
            Err(e) => return e,
        };
        let norm_newpath = match self.normalize_path_at(cage_id, newdirfd, newpath) {
            Ok(path) => path,
            Err(e) => return e,
        };
        self.link_resolved_paths(
            &norm_oldpath,
            &norm_newpath,
            flags & libc::AT_SYMLINK_FOLLOW != 0,
        )
    }

    fn link_resolved_paths(
        &mut self,
        norm_oldpath: &str,
        norm_newpath: &str,
        follow_old: bool,
    ) -> i32 {
        let old_idx = match self.resolve_path(norm_oldpath, follow_old) {
            Ok(idx) => idx,
            Err(e) => return e,
        };

        if self.nodes[old_idx].node_type == NodeType::Dir {
            return -1; // EPERM
        }

        // Ensure newpath does not exist.
        match self.resolve_path(norm_newpath, false) {
            Ok(_) => return -17, // EEXIST
            Err(-2) => {}
            Err(e) => return e,
        };

        // open(O_CREAT) behaviour.
        let (parent_idx, filename) = match self.resolve_parent_and_name(norm_newpath) {
            Ok(parts) => parts,
            Err(e) => return e,
        };

        if filename == "." || filename == ".." {
            return -1; // EPERM
        }

        if filename.len() >= MAX_NODE_NAME {
            return -36; // ENAMETOOLONG
        }

        let mode = self.nodes[old_idx].mode;

        // Create new Lnk, update target.
        let new_idx = self.create_node(&filename, NodeType::Lnk, mode);
        self.add_child(parent_idx, new_idx);
        if let NodeInfo::HardLink { target } = &mut self.nodes[new_idx].info {
            *target = old_idx;
        } else {
            self.nodes[new_idx].info = NodeInfo::HardLink { target: old_idx };
        }
        self.update_mtime(parent_idx);
        self.update_ctime(parent_idx);
        self.update_ctime(old_idx);
        self.update_mtime(new_idx);
        self.update_ctime(new_idx);

        0
    }

    pub fn symlink(&mut self, cage_id: u64, target: &str, linkpath: &str) -> i32 {
        let norm_linkpath = self.normalize_path_for_cage(cage_id, linkpath);
        self.symlink_resolved_path(target, &norm_linkpath)
    }

    pub fn symlinkat(&mut self, cage_id: u64, target: &str, newdirfd: i32, linkpath: &str) -> i32 {
        let norm_linkpath = match self.normalize_path_at(cage_id, newdirfd, linkpath) {
            Ok(path) => path,
            Err(e) => return e,
        };
        self.symlink_resolved_path(target, &norm_linkpath)
    }

    fn symlink_resolved_path(&mut self, target: &str, norm_linkpath: &str) -> i32 {
        match self.resolve_path(norm_linkpath, false) {
            Ok(_) => return -17, // EEXIST
            Err(-2) => {}
            Err(e) => return e,
        };

        let (parent_idx, filename) = match self.resolve_parent_and_name(norm_linkpath) {
            Ok(parts) => parts,
            Err(e) => return e,
        };

        if filename == "." || filename == ".." {
            return -17; // EEXIST
        }

        if filename.len() >= MAX_NODE_NAME {
            return -36; // ENAMETOOLONG
        }

        let new_idx = self.create_node(&filename, NodeType::Lnk, 0o777);
        self.nodes[new_idx].info = NodeInfo::Symlink {
            target: target.to_string(),
        };
        self.nodes[new_idx].total_size = target.len();
        self.add_child(parent_idx, new_idx);
        self.update_mtime(parent_idx);
        self.update_ctime(parent_idx);
        self.update_mtime(new_idx);
        self.update_ctime(new_idx);

        0
    }

    pub fn readlink(&mut self, cage_id: u64, path: &str) -> Result<String, i32> {
        let norm_path = self.normalize_path_for_cage(cage_id, path);
        self.readlink_resolved_path(&norm_path)
    }

    pub fn readlinkat(&mut self, cage_id: u64, dirfd: i32, path: &str) -> Result<String, i32> {
        let norm_path = match self.normalize_path_at(cage_id, dirfd, path) {
            Ok(path) => path,
            Err(e) => return Err(e),
        };
        self.readlink_resolved_path(&norm_path)
    }

    fn readlink_resolved_path(&mut self, norm_path: &str) -> Result<String, i32> {
        let node_idx = self.resolve_path(norm_path, false)?;
        let target = match &self.nodes[node_idx].info {
            NodeInfo::Symlink { target } => target.clone(),
            _ => return Err(-22), // EINVAL
        };
        self.update_atime(node_idx);
        Ok(target)
    }

    pub fn rename(&mut self, cage_id: u64, oldpath: &str, newpath: &str) -> i32 {
        let norm_oldpath = self.normalize_path_for_cage(cage_id, oldpath);
        let norm_newpath = self.normalize_path_for_cage(cage_id, newpath);
        self.rename_resolved_paths(&norm_oldpath, &norm_newpath)
    }

    pub fn renameat(
        &mut self,
        cage_id: u64,
        olddirfd: i32,
        oldpath: &str,
        newdirfd: i32,
        newpath: &str,
    ) -> i32 {
        let norm_oldpath = match self.normalize_path_at(cage_id, olddirfd, oldpath) {
            Ok(path) => path,
            Err(e) => return e,
        };
        let norm_newpath = match self.normalize_path_at(cage_id, newdirfd, newpath) {
            Ok(path) => path,
            Err(e) => return e,
        };
        self.rename_resolved_paths(&norm_oldpath, &norm_newpath)
    }

    fn rename_resolved_paths(&mut self, norm_oldpath: &str, norm_newpath: &str) -> i32 {
        if norm_oldpath == "/" {
            return -1; // EPERM
        }

        let (old_parent_idx, old_name) = match self.resolve_parent_and_name(&norm_oldpath) {
            Ok(parts) => parts,
            Err(e) => return e,
        };
        let old_idx = match self.resolve_path(&norm_oldpath, false) {
            Ok(idx) => idx,
            Err(e) => return e,
        };

        if old_name == "." || old_name == ".." {
            return -1; // EPERM
        }

        if norm_newpath == "/" {
            return -1; // EPERM
        }

        let (new_parent_idx, new_name) = match self.resolve_parent_and_name(&norm_newpath) {
            Ok(parts) => parts,
            Err(e) => return e,
        };

        if new_name == "." || new_name == ".." {
            return -1; // EPERM
        }

        if new_name.len() >= MAX_NODE_NAME {
            return -36; // ENAMETOOLONG
        }

        if self.nodes[old_idx].node_type == NodeType::Dir
            && norm_newpath.starts_with(&format!("{}/", norm_oldpath.trim_end_matches('/')))
        {
            return -22; // EINVAL
        }

        match self.resolve_path(&norm_newpath, false) {
            Ok(existing_idx) => {
                if existing_idx == old_idx {
                    return 0;
                }

                if self.nodes[existing_idx].node_type == NodeType::Dir {
                    return -1; // EPERM
                }

                self.remove_child(existing_idx);
                self.update_mtime(new_parent_idx);
                self.update_ctime(new_parent_idx);
                self.update_ctime(existing_idx);
                self.unlink_node(existing_idx);
            }
            Err(-2) => {}
            Err(e) => return e,
        }

        self.remove_child(old_idx);
        self.nodes[old_idx].name = new_name;
        self.add_child(new_parent_idx, old_idx);
        self.update_mtime(old_parent_idx);
        self.update_ctime(old_parent_idx);
        if new_parent_idx != old_parent_idx {
            self.update_mtime(new_parent_idx);
            self.update_ctime(new_parent_idx);
        }
        self.update_ctime(old_idx);

        0
    }

    /// chmod: update only permission bits and preserve the file type bits.
    pub fn chmod(&mut self, cage_id: u64, path: &str, mode: u32) -> i32 {
        let norm_path = self.normalize_path_for_cage(cage_id, path);
        self.chmod_resolved_path(&norm_path, mode)
    }

    pub fn chmodat(&mut self, cage_id: u64, dirfd: i32, path: &str, mode: u32) -> i32 {
        let norm_path = match self.normalize_path_at(cage_id, dirfd, path) {
            Ok(path) => path,
            Err(e) => return e,
        };
        self.chmod_resolved_path(&norm_path, mode)
    }

    fn chmod_resolved_path(&mut self, norm_path: &str, mode: u32) -> i32 {
        let node_idx = match self.resolve_path(&norm_path, true) {
            Ok(idx) => idx,
            Err(e) => return e,
        };

        self.nodes[node_idx].mode = (self.nodes[node_idx].mode & !0o777) | (mode & 0o777);
        self.update_ctime(node_idx);

        0
    }

    pub fn fchmod(&mut self, cage_id: u64, fd: u64, mode: u32) -> i32 {
        let (node_idx, _) = match self.get_node_and_flags(cage_id, fd) {
            Ok(entry) => entry,
            Err(e) => return e,
        };

        self.nodes[node_idx].mode = (self.nodes[node_idx].mode & !0o777) | (mode & 0o777);
        self.update_ctime(node_idx);

        0
    }

    pub fn chown(&mut self, cage_id: u64, path: &str) -> i32 {
        let norm_path = self.normalize_path_for_cage(cage_id, path);
        match self.resolve_path(&norm_path, true) {
            Ok(_) => 0,
            Err(e) => e,
        }
    }

    pub fn chownat(&mut self, cage_id: u64, dirfd: i32, path: &str) -> i32 {
        let norm_path = match self.normalize_path_at(cage_id, dirfd, path) {
            Ok(path) => path,
            Err(e) => return e,
        };
        match self.resolve_path(&norm_path, true) {
            Ok(_) => 0,
            Err(e) => e,
        }
    }

    pub fn utimensat(&mut self, cage_id: u64, dirfd: i32, path: Option<&str>) -> i32 {
        let node_idx = match path {
            Some(path) => {
                let norm_path = match self.normalize_path_at(cage_id, dirfd, path) {
                    Ok(path) => path,
                    Err(e) => return e,
                };
                match self.resolve_path(&norm_path, true) {
                    Ok(idx) => idx,
                    Err(e) => return e,
                }
            }
            None => {
                let Ok(entry) = fdtables::translate_virtual_fd(cage_id, dirfd as u64) else {
                    return -9;
                };
                entry.underfd as usize
            }
        };

        if node_idx >= self.nodes.len() {
            return -9;
        }

        self.update_atime(node_idx);
        self.update_mtime(node_idx);
        self.update_ctime(node_idx);
        0
    }

    pub fn mknod(&mut self, cage_id: u64, path: &str, mode: u32) -> i32 {
        let node_type = match mode & S_IFMT {
            S_IFIFO => NodeType::Pip,
            S_IFREG | 0 => NodeType::Reg,
            _ => return -1, // EPERM
        };

        let norm_path = self.normalize_path_for_cage(cage_id, path);
        if self.resolve_path(&norm_path, true).is_ok() {
            return -17; // EEXIST
        }

        let (parent_idx, name) = match self.resolve_parent_and_name(&norm_path) {
            Ok(parent) => parent,
            Err(e) => return e,
        };

        if name == "." || name == ".." {
            return -17; // EEXIST
        }
        if name.len() >= MAX_NODE_NAME {
            return -36; // ENAMETOOLONG
        }

        let node_idx = self.create_node(&name, node_type, mode);
        self.add_child(parent_idx, node_idx);
        self.update_mtime(parent_idx);
        self.update_ctime(parent_idx);
        self.update_mtime(node_idx);
        self.update_ctime(node_idx);

        0
    }

    pub fn truncate(&mut self, cage_id: u64, path: &str, length: i64) -> i32 {
        if length < 0 {
            return -22; // EINVAL
        }

        let norm_path = self.normalize_path_for_cage(cage_id, path);
        let node_idx = match self.resolve_path(&norm_path, true) {
            Ok(idx) => idx,
            Err(e) => return e,
        };

        match self.nodes[node_idx].node_type {
            NodeType::Reg => {}
            NodeType::Dir => return -21, // EISDIR
            _ => return -22,             // EINVAL
        }

        self.truncate_node(node_idx, length as usize);
        self.update_mtime(node_idx);
        self.update_ctime(node_idx);

        0
    }

    pub fn ftruncate(&mut self, cage_id: u64, fd: u64, length: i64) -> i32 {
        if length < 0 {
            return -22; // EINVAL
        }

        let (node_idx, flags) = match self.get_node_and_flags(cage_id, fd) {
            Ok((n, f)) => (n, f),
            Err(e) => return e,
        };

        if (flags & O_ACCMODE) == O_RDONLY {
            return -9; // EBADF
        }

        match self.nodes[node_idx].node_type {
            NodeType::Reg => {}
            NodeType::Dir => return -21, // EISDIR
            _ => return -22,             // EINVAL
        }

        self.truncate_node(node_idx, length as usize);
        self.update_mtime(node_idx);
        self.update_ctime(node_idx);

        0
    }

    /// mkdir: create a directory.
    pub fn mkdir(&mut self, cage_id: u64, path: &str, mode: u32) -> i32 {
        let norm_path = self.normalize_path_for_cage(cage_id, path);
        if self.resolve_path(&norm_path, true).is_ok() {
            return -17; // EEXIST
        }

        if norm_path == "/" {
            return -17; // EEXIST
        }

        let (parent_idx, dirname) = match self.resolve_parent_and_name(&norm_path) {
            Ok(p) => p,
            Err(e) => return e,
        };

        if dirname == "." || dirname == ".." {
            return -17; // EEXIST
        }

        let dir_idx = self.create_node(&dirname, NodeType::Dir, mode);
        self.add_child(parent_idx, dir_idx);

        // Add . and ..
        let dot_idx = self.create_node(".", NodeType::Lnk, 0);
        self.nodes[dot_idx].info = NodeInfo::HardLink { target: dir_idx };
        self.add_child(dir_idx, dot_idx);

        let dotdot_idx = self.create_node("..", NodeType::Lnk, 0);
        self.nodes[dotdot_idx].info = NodeInfo::HardLink { target: parent_idx };
        self.add_child(dir_idx, dotdot_idx);
        self.update_mtime(parent_idx);
        self.update_ctime(parent_idx);
        self.update_mtime(dir_idx);
        self.update_ctime(dir_idx);

        0
    }
}
