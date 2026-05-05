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

const DIRENT64_FIXED_SIZE: usize = 8 + 8 + 2 + 1;
const IMFS_BLOCK_SIZE: i32 = 512;

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
    state.nodes[dot_idx].info = NodeInfo::Lnk { target: root_idx };
    state.add_child(root_idx, dot_idx);

    let dotdot_idx = state.create_node("..", NodeType::Lnk, 0);
    state.nodes[dotdot_idx].info = NodeInfo::Lnk { target: root_idx };
    state.add_child(root_idx, dotdot_idx);

    *IMFS.lock().unwrap() = Some(state);
}

impl ImfsState {
    fn dirent_type(&self, node_idx: usize) -> u8 {
        let mut idx = node_idx;

        while let NodeInfo::Lnk { target } = &self.nodes[idx].info {
            idx = *target;
        }

        match self.nodes[idx].node_type {
            NodeType::Dir => libc::DT_DIR,
            NodeType::Reg => libc::DT_REG,
            NodeType::Lnk => libc::DT_LNK,
            _ => libc::DT_UNKNOWN,
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
        self.nodes[idx].node_type = NodeType::Free;
        self.nodes[idx].info = NodeInfo::Free;
        self.node_free_list.push(idx);
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

    // =====================================================================
    //  Path resolution
    // =====================================================================

    /// normalize_path_for_cage:
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

    /// Walk the node tree to find the node at the given absolute path.
    /// Returns ENOENT if a component is missing, ENOTDIR if an intermediate
    /// component is not a directory. Follows symlinks (Lnk nodes) during traversal.
    fn find_node_result(&self, path: &str) -> Result<usize, i32> {
        if path == "/" {
            return Ok(self.root_idx);
        }

        let components: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if components.is_empty() {
            return Ok(self.root_idx);
        }

        let mut current = self.root_idx;

        for component in &components {
            let children = match &self.nodes[current].info {
                NodeInfo::Dir { children } => children,
                _ => return Err(-20), // ENOTDIR
            };

            let mut found = None;
            for entry in children {
                if entry.name == *component {
                    let child = &self.nodes[entry.node_idx];
                    // Follow symlinks.
                    found = Some(match child.link_target() {
                        Some(target) => target,
                        None => entry.node_idx,
                    });
                    break;
                }
            }

            current = match found {
                Some(idx) => idx,
                None => return Err(-2), // ENOENT
            };
        }

        Ok(current)
    }

    /// Split a path into its parent directory and final filename.
    /// Returns ENOENT if a parent component is missing, ENOTDIR if an
    /// intermediate component is not a directory.
    fn find_parent_and_name_result(&self, path: &str) -> Result<(usize, String), i32> {
        let components: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if components.is_empty() {
            return Err(-2); // ENOENT
        }

        let filename = components.last().unwrap().to_string();

        if components.len() == 1 {
            return Ok((self.root_idx, filename));
        }

        let mut current = self.root_idx;
        for component in &components[..components.len() - 1] {
            let children = match &self.nodes[current].info {
                NodeInfo::Dir { children } => children,
                _ => return Err(-20), // ENOTDIR
            };

            let mut found = None;
            for entry in children {
                if entry.name == *component {
                    found = Some(match self.nodes[entry.node_idx].link_target() {
                        Some(target) => target,
                        None => entry.node_idx,
                    });
                    break;
                }
            }
            current = match found {
                Some(idx) => idx,
                None => return Err(-2), // ENOENT
            };
        }

        if self.nodes[current].node_type != NodeType::Dir {
            return Err(-20); // ENOTDIR
        }

        Ok((current, filename))
    }

    /// Resolve a path to the backing node without following the final component
    /// if it is a link node. Parent components are still resolved normally.
    fn find_node_no_follow_final_result(&self, path: &str) -> Result<usize, i32> {
        if path == "/" {
            return Ok(self.root_idx);
        }

        let (parent_idx, filename) = self.find_parent_and_name_result(path)?;
        let children = match &self.nodes[parent_idx].info {
            NodeInfo::Dir { children } => children,
            _ => return Err(-20), // ENOTDIR
        };

        children
            .iter()
            .find(|entry| entry.name == filename)
            .map(|entry| entry.node_idx)
            .ok_or(-2)
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

        if dirfd == libc::AT_FDCWD {
            return Ok(self.normalize_path_for_cage(cage_id, path));
        }

        let entry = match fdtables::translate_virtual_fd(cage_id, dirfd as u64) {
            Ok(entry) => entry,
            Err(_) => return Err(-9), // EBADF
        };

        let mut node_idx = entry.underfd as usize;
        while let NodeInfo::Lnk { target } = &self.nodes[node_idx].info {
            node_idx = *target;
        }

        if self.nodes[node_idx].node_type != NodeType::Dir {
            return Err(-20); // ENOTDIR
        }

        let base = self.absolute_path_for_node(node_idx);
        Ok(self.normalize_path_for_cage(cage_id, &format!("{}/{}", base, path)))
    }

    // =====================================================================
    //  Internal chunk read/write
    // =====================================================================

    /// Read bytes from a regular file's chunk chain starting at the given byte offset.
    /// Walks the linked list of chunks, skipping past the offset, then copies data
    /// into buf. Returns the number of bytes actually read (may be less than buf.len()
    /// if EOF is reached).

    fn get_offset(&self, cageid: u64, fd: u64) -> i64 {
        let underfd = self.fd_info.get(&(cageid, fd)).unwrap().lock().unwrap();

        underfd.offset
    }

    fn set_offset(&self, cageid: u64, fd: u64, offset: i64) {
        let mut underfd = self.fd_info.get(&(cageid, fd)).unwrap().lock().unwrap();

        underfd.offset = offset;
    }

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

    // Helper function to get the node_idx and flag for a give cageid and fd.
    //
    // In case the node_idx points to a Lnk, it follows the link until we hit a real Node.
    // This immediately adds support for reading symlinked files.
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
        while let NodeInfo::Lnk { target } = &self.nodes[idx].info {
            idx = *target;
        }

        return Ok((idx as usize, flags));
    }

    // =====================================================================
    //  Public Filesystem operations
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
        if let Some(cwd) = self.cwd_info.get_mut(&cage_id) {
            *cwd = norm_path.to_string();
            0
        } else {
            -1
        }
    }

    /// xstat
    pub fn stat(&mut self, cage_id: u64, path: &str, statbuf: &mut stat) -> i32 {
        let norm_path = self.normalize_path_for_cage(cage_id, path);

        let node_idx = match self.find_node_result(&norm_path) {
            Ok(idx) => idx,
            Err(e) => return e,
        };

        let node = &self.nodes[node_idx];

        *statbuf = stat {
            st_dev: 1,
            st_ino: node_idx as u64,
            st_mode: node.mode,
            st_nlink: 1,
            st_uid: 0, //node.owner,
            st_gid: 0, //node.group,
            st_rdev: 0,
            st_size: node.total_size as u64,
            st_blksize: IMFS_BLOCK_SIZE,
            st_blocks: (node.total_size / IMFS_BLOCK_SIZE as usize) as u32,
            st_atim: [0, 0],
            st_mtim: [0, 0],
            st_ctim: [0, 0],
        };

        0
    }

    /// fxstat
    pub fn fstat(&mut self, cage_id: u64, fd: u64, statbuf: &mut stat) -> i32 {
        let (node_idx, _) = match self.get_node_and_flags(cage_id, fd) {
            Ok((n, f)) => (n, f),
            Err(e) => return e,
        };

        let node = &self.nodes[node_idx];

        *statbuf = stat {
            st_dev: 1,
            st_ino: node_idx as u64,
            st_mode: node.mode,
            st_nlink: 1,
            st_uid: 0, //node.owner,
            st_gid: 0, //node.group,
            st_rdev: 0,
            st_size: node.total_size as u64,
            st_blksize: IMFS_BLOCK_SIZE,
            st_blocks: (node.total_size / IMFS_BLOCK_SIZE as usize) as u32,
            st_atim: [0, 0],
            st_mtim: [0, 0],
            st_ctim: [0, 0],
        };

        0
    }

    /// rmdir: remove an empty directory.
    pub fn rmdir(&mut self, cage_id: u64, path: &str) -> i32 {
        let norm_path = self.normalize_path_for_cage(cage_id, path);
        let node_idx = match self.find_node_result(&norm_path) {
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

        self.remove_child(node_idx);
        self.nodes[node_idx].doomed = true;

        if self.nodes[node_idx].in_use == 0 {
            self.reclaim_node(node_idx);
        }

        0
    }

    /// open: create or open a file. Returns the fd allocated by fdtables.
    pub fn open(&mut self, cage_id: u64, path: &str, flags: i32, mode: u32) -> i32 {
        let norm_path = self.normalize_path_for_cage(cage_id, path);
        let node_idx = if let Ok(idx) = self.find_node_result(&norm_path) {
            if (flags & O_EXCL) != 0 && (flags & O_CREAT) != 0 {
                return -17; // EEXIST
            }
            if self.nodes[idx].node_type == NodeType::Dir && (flags & O_DIRECTORY) == 0 {
                return -21; // EISDIR
            }

            // Check permissions.
            let m = self.nodes[idx].mode;
            match flags & O_ACCMODE {
                O_RDONLY if m & S_IRUSR == 0 => return -13,
                O_WRONLY if m & S_IWUSR == 0 => return -13,
                O_RDWR if m & S_IRUSR == 0 || m & S_IWUSR == 0 => return -13,
                _ => {}
            }
            idx
        } else {
            if (flags & O_CREAT) == 0 {
                return -2; // ENOENT
            }
            let (parent_idx, filename) = match self.find_parent_and_name_result(&norm_path) {
                Ok(p) => p,
                Err(e) => return e,
            };
            if filename.len() >= MAX_NODE_NAME {
                return -36; // ENAMETOOLONG
            }
            let new_idx = self.create_node(&filename, NodeType::Reg, mode);
            self.add_child(parent_idx, new_idx);
            new_idx
        };

        self.nodes[node_idx].in_use += 1;

        // Allocate fd via fdtables. underfd = node index, perfdinfo = flags.
        match fdtables::get_unused_virtual_fd(
            cage_id,
            IMFS_FDKIND,
            node_idx as u64, // underfd: which node
            false,
            0,
        ) {
            Ok(vfd) => {
                // Track the offset for this fd.
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

    pub fn openat(&mut self, cage_id: u64, dirfd: i32, path: &str, flags: i32, mode: u32) -> i32 {
        let norm_path = match self.normalize_path_at(cage_id, dirfd, path) {
            Ok(path) => path,
            Err(e) => return e,
        };

        let node_idx = if let Ok(idx) = self.find_node_result(&norm_path) {
            if (flags & O_EXCL) != 0 && (flags & O_CREAT) != 0 {
                return -17; // EEXIST
            }
            if self.nodes[idx].node_type == NodeType::Dir && (flags & O_DIRECTORY) == 0 {
                return -21; // EISDIR
            }

            let m = self.nodes[idx].mode;
            match flags & O_ACCMODE {
                O_RDONLY if m & S_IRUSR == 0 => return -13,
                O_WRONLY if m & S_IWUSR == 0 => return -13,
                O_RDWR if m & S_IRUSR == 0 || m & S_IWUSR == 0 => return -13,
                _ => {}
            }
            idx
        } else {
            if (flags & O_CREAT) == 0 {
                return -2; // ENOENT
            }
            let (parent_idx, filename) = match self.find_parent_and_name_result(&norm_path) {
                Ok(p) => p,
                Err(e) => return e,
            };
            if filename.len() >= MAX_NODE_NAME {
                return -36; // ENAMETOOLONG
            }
            let new_idx = self.create_node(&filename, NodeType::Reg, mode);
            self.add_child(parent_idx, new_idx);
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

        // Return EBADF for reads on non regular files.
        // TODO: Implement pipe reads.
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

        // Advance the offset.
        self.set_offset(cage_id, fd, offset + n as i64);

        n as i32
    }

    /// pread: read at a specific offset without changing the fd offset.
    pub fn pread(&mut self, cage_id: u64, fd: u64, buf: &mut [u8], offset: i64) -> i32 {
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

        self.read_from_node(node_idx, offset as usize, buf) as i32
    }

    /// write: write to a file at the current offset.
    pub fn write(&mut self, cage_id: u64, fd: u64, buf: &[u8]) -> i32 {
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

        let offset = if (flags & O_APPEND) != 0 {
            self.nodes[node_idx].total_size as i64
        } else {
            self.get_offset(cage_id, fd)
        };

        let n = self.write_to_node(node_idx, offset as usize, buf);

        self.set_offset(cage_id, fd, offset + n as i64);

        n as i32
    }

    /// pwrite: write at a specific offset without changing the fd offset.
    pub fn pwrite(&mut self, cage_id: u64, fd: u64, buf: &[u8], offset: i64) -> i32 {
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

        self.write_to_node(node_idx, offset as usize, buf) as i32
    }

    /// lseek: reposition the fd offset.
    pub fn lseek(&mut self, cage_id: u64, fd: u64, offset: i64, whence: i32) -> i32 {
        let (node_idx, _) = match self.get_node_and_flags(cage_id, fd) {
            Ok((n, _)) => (n, ..),
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

        self.set_offset(cage_id, fd, new_offset);

        new_offset as i32
    }

    /// fcntl: only F_GETFL implemented — returns flags from fdtables perfdinfo.
    pub fn fcntl(&self, cage_id: u64, fd: u64, op: i32, _arg: i32) -> i32 {
        match op {
            F_GETFL => {
                let fd_info = self.fd_info.get(&(cage_id, fd)).unwrap().lock().unwrap();

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
        if norm_path == "/" {
            return -1; // EPERM
        }

        let parent_path = match norm_path.rsplit_once('/') {
            Some(("", _)) => "/",
            Some((parent, _)) => parent,
            None => return -2, // ENOENT
        };

        let parent_idx = match self.find_node_result(parent_path) {
            Ok(idx) => idx,
            Err(e) => return e,
        };

        if self.nodes[parent_idx].node_type != NodeType::Dir {
            return -20; // ENOTDIR
        }

        let (_, filename) = match self.find_parent_and_name_result(&norm_path) {
            Ok(parts) => parts,
            Err(e) => return e,
        };

        if filename == "." || filename == ".." {
            return -1; // EPERM
        }

        let node_idx = match self.find_node_no_follow_final_result(&norm_path) {
            Ok(idx) => idx,
            Err(e) => return e,
        };

        if self.nodes[node_idx].node_type == NodeType::Dir {
            return -21; // EISDIR
        };

        self.remove_child(node_idx);
        self.nodes[node_idx].doomed = true;

        if self.nodes[node_idx].in_use == 0 {
            self.reclaim_node(node_idx);
        }

        0
    }

    /// link: (int cage_id, const char *oldpath, const char *newpath) {
    pub fn link(&mut self, cage_id: u64, oldpath: &str, newpath: &str) -> i32 {
        // Ensure old path exists.
        let norm_oldpath = self.normalize_path_for_cage(cage_id, oldpath);
        let old_idx = match self.find_node_result(&norm_oldpath) {
            Ok(idx) => idx,
            Err(e) => return e,
        };

        if self.nodes[old_idx].node_type == NodeType::Dir {
            return -1; // EPERM
        }

        // Ensure newpath does not exist.
        let norm_newpath = self.normalize_path_for_cage(cage_id, newpath);
        match self.find_node_no_follow_final_result(&norm_newpath) {
            Ok(_) => return -17, // EEXIST
            Err(-2) => {}
            Err(e) => return e,
        };

        // open(O_CREAT) behaviour.
        let (parent_idx, filename) = match self.find_parent_and_name_result(&norm_newpath) {
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
        if let NodeInfo::Lnk { target } = &mut self.nodes[new_idx].info {
            *target = old_idx;
        }

        0
    }

    pub fn rename(&mut self, cage_id: u64, oldpath: &str, newpath: &str) -> i32 {
        let norm_oldpath = self.normalize_path_for_cage(cage_id, oldpath);
        if norm_oldpath == "/" {
            return -1; // EPERM
        }

        let old_parent_path = match norm_oldpath.rsplit_once('/') {
            Some(("", _)) => "/",
            Some((parent, _)) => parent,
            None => return -2, // ENOENT
        };

        let old_parent_idx = match self.find_node_result(old_parent_path) {
            Ok(idx) => idx,
            Err(e) => return e,
        };

        if self.nodes[old_parent_idx].node_type != NodeType::Dir {
            return -20; // ENOTDIR
        }

        let old_idx = match self.find_node_no_follow_final_result(&norm_oldpath) {
            Ok(idx) => idx,
            Err(e) => return e,
        };

        let (_, old_name) = match self.find_parent_and_name_result(&norm_oldpath) {
            Ok(parts) => parts,
            Err(e) => return e,
        };

        if old_name == "." || old_name == ".." {
            return -1; // EPERM
        }

        let norm_newpath = self.normalize_path_for_cage(cage_id, newpath);
        if norm_newpath == "/" {
            return -1; // EPERM
        }

        let new_parent_path = match norm_newpath.rsplit_once('/') {
            Some(("", _)) => "/",
            Some((parent, _)) => parent,
            None => return -2, // ENOENT
        };

        let new_parent_idx = match self.find_node_result(new_parent_path) {
            Ok(idx) => idx,
            Err(e) => return e,
        };

        if self.nodes[new_parent_idx].node_type != NodeType::Dir {
            return -20; // ENOTDIR
        }

        let (_, new_name) = match self.find_parent_and_name_result(&norm_newpath) {
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
            && norm_newpath.starts_with(&(norm_oldpath.clone() + "/"))
        {
            return -22; // EINVAL
        }

        match self.find_node_no_follow_final_result(&norm_newpath) {
            Ok(existing_idx) => {
                if existing_idx == old_idx {
                    return 0;
                }

                if self.nodes[existing_idx].node_type == NodeType::Dir {
                    return -1; // EPERM
                }

                self.remove_child(existing_idx);
                self.nodes[existing_idx].doomed = true;

                if self.nodes[existing_idx].in_use == 0 {
                    self.reclaim_node(existing_idx);
                }
            }
            Err(-2) => {}
            Err(e) => return e,
        }

        self.remove_child(old_idx);
        self.nodes[old_idx].name = new_name;
        self.add_child(new_parent_idx, old_idx);

        0
    }

    /// chmod: update only permission bits and preserve the file type bits.
    pub fn chmod(&mut self, cage_id: u64, path: &str, mode: u32) -> i32 {
        let norm_path = self.normalize_path_for_cage(cage_id, path);
        let node_idx = match self.find_node_result(&norm_path) {
            Ok(idx) => idx,
            Err(e) => return e,
        };

        self.nodes[node_idx].mode = (self.nodes[node_idx].mode & !0o777) | (mode & 0o777);

        0
    }

    /// mkdir: create a directory.
    pub fn mkdir(&mut self, cage_id: u64, path: &str, mode: u32) -> i32 {
        let norm_path = self.normalize_path_for_cage(cage_id, path);
        if self.find_node_result(&norm_path).is_ok() {
            return -17; // EEXIST
        }

        if norm_path == "/" {
            return -17; // EEXIST
        }

        let parent_path = match norm_path.rsplit_once('/') {
            Some(("", _)) => "/",
            Some((parent, _)) => parent,
            None => return -2, // ENOENT
        };

        let parent_idx = match self.find_node_result(parent_path) {
            Ok(idx) => idx,
            Err(e) => return e,
        };

        if self.nodes[parent_idx].node_type != NodeType::Dir {
            return -20; // ENOTDIR
        }

        let (_, dirname) = match self.find_parent_and_name_result(&norm_path) {
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
        self.nodes[dot_idx].info = NodeInfo::Lnk { target: dir_idx };
        self.add_child(dir_idx, dot_idx);

        let dotdot_idx = self.create_node("..", NodeType::Lnk, 0);
        self.nodes[dotdot_idx].info = NodeInfo::Lnk { target: parent_idx };
        self.add_child(dir_idx, dotdot_idx);

        0
    }
}
