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
use grate_rs::constants::mman::{MAP_ANON, MAP_SHARED, PROT_READ, PROT_WRITE};
use grate_rs::constants::{SYS_MMAP, SYS_MUNMAP};
use grate_rs::{copy_data_between_cages, getcageid, make_threei_call};

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

    /// Live cage-side mappings of RegMapped files.
    ///
    /// Keyed on `(cage_id, cage_vaddr)` because that's what `munmap`
    /// receives.  Value is `(node_idx, len, file_offset)` so we know
    /// which `mmap_refs` to decrement, which byte range the cage view
    /// covers, and how much to forward to RawPOSIX for the actual
    /// unmap.  Entries are inserted by the mmap handler and removed by
    /// munmap; fork and exit only clone/drop entries.
    pub mmap_tracking: HashMap<(u64, u64), (usize, usize, usize)>,
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
        mmap_tracking: HashMap::new(),
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

        while let NodeInfo::Lnk { target } = &self.nodes[idx].info {
            idx = *target;
        }

        match self.nodes[idx].node_type {
            NodeType::Dir => DT_DIR,
            NodeType::Reg | NodeType::RegMapped => DT_REG,
            NodeType::Lnk => DT_LNK,
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
            NodeInfo::RegMapped { .. } => {
                self.free_mapped_backing(idx);
                None
            }
            _ => None,
        };
        self.reclaim_chunk_chain(chunk_head);

        self.nodes[idx].node_type = NodeType::Free;
        self.nodes[idx].info = NodeInfo::Free;
        self.node_free_list.push(idx);
    }

    fn node_mmap_refs(&self, idx: usize) -> u32 {
        match &self.nodes[idx].info {
            NodeInfo::RegMapped { mmap_refs, .. } => *mmap_refs,
            _ => 0,
        }
    }

    fn try_reclaim_doomed_node(&mut self, idx: usize) {
        if self.nodes[idx].doomed && self.nodes[idx].in_use == 0 && self.node_mmap_refs(idx) == 0 {
            self.reclaim_node(idx);
        }
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
                            NodeInfo::Lnk { target } if *target == node_idx
                        )
                })
                .count() as u32,
        }
    }

    fn unlink_node(&mut self, node_idx: usize) {
        if let NodeInfo::Lnk { target } = &self.nodes[node_idx].info {
            let target = *target;
            self.update_ctime(target);
            if self.link_count(target) == 0 {
                self.nodes[target].doomed = true;
                self.try_reclaim_doomed_node(target);
            }
            self.reclaim_node(node_idx);
            return;
        }

        if self.link_count(node_idx) == 0 {
            self.nodes[node_idx].doomed = true;
            self.try_reclaim_doomed_node(node_idx);
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
    //  RegMapped backing management
    // =====================================================================
    //
    // RegMapped nodes hold their bytes in a host mmap'd page range
    // (anonymous, shared) rather than the chunk arena.  This is what
    // makes the file mappable by a cage: the same host pages can be
    // aliased into the cage's vmmap via SYS_MMAP with MAP_FIXED, and
    // every cage that maps the file ends up backed by the same pages
    // — that's what gives MAP_SHARED its cross-cage semantics.
    //
    // The mapping is allocated lazily on first grow (write or
    // ftruncate) so opens that never touch the file don't pay an
    // mmap syscall.

    /// Allocate the host mapping for a `RegMapped` node, or grow it
    /// to at least `min_capacity` bytes.  No-op if the current
    /// capacity already covers it.
    ///
    /// Returns Ok(()) on success, or:
    ///   - `EINVAL` if the node isn't a RegMapped.
    ///   - `EBUSY` if the mapping needs to grow but `mmap_refs > 0`
    ///     — moving the region would invalidate live cage mappings.
    ///   - `ENOMEM` if `mmap` failed.
    ///
    /// On grow, the existing region's contents are copied into the
    /// new (larger) region and the old region is unmapped.
    fn ensure_mapped_backing(&mut self, node_idx: usize, min_capacity: usize) -> Result<(), i32> {
        let (current_host, current_cap, refs) = match &self.nodes[node_idx].info {
            NodeInfo::RegMapped {
                host_addr,
                capacity,
                mmap_refs,
            } => (*host_addr, *capacity, *mmap_refs),
            _ => return Err(grate_rs::constants::error::EINVAL),
        };

        if min_capacity <= current_cap {
            return Ok(());
        }
        if refs > 0 {
            // Cages still have this region mapped; growing would
            // require moving it, which would silently invalidate
            // those mappings.  Refuse instead.
            return Err(grate_rs::constants::error::EBUSY);
        }

        // Round up to page size — host kernel mmap will round anyway,
        // and tracking the rounded value lets us check capacity
        // bounds against the actual mapped extent.
        const PAGE_SIZE: usize = 4096;
        let new_cap = ((min_capacity + PAGE_SIZE - 1) / PAGE_SIZE) * PAGE_SIZE;

        // Allocate the host mapping via threei → RawPOSIX.  NULL
        // address hint, anonymous + shared so RawPOSIX gives us
        // real host pages (page-cache shareable) rather than a
        // private mapping — that's what makes the later cage-side
        // MAP_FIXED alias the same physical pages.  `fd = -1` (sent
        // as u64::MAX so the sign-extension survives the threei
        // boundary), `offset = 0`.
        let thiscage = getcageid();
        let ret = make_threei_call(
            SYS_MMAP as u32,
            0,
            thiscage,
            thiscage,
            0,
            0, // addr: NULL
            new_cap as u64,
            0, // len
            (PROT_READ | PROT_WRITE) as u64,
            0, // prot
            (MAP_ANON | MAP_SHARED) as u64,
            0, // flags
            u64::MAX,
            0, // fd = -1
            0,
            0, // offset
            0,
        );
        // mmap returns a wasm32 user-space address which can have bit
        // 31 set (e.g. find_map_space hands out pages near the top of
        // the 4GB vmmap on an empty cage).  Such returns look negative
        // as i32 and grate-rs's make_threei_call collapses any
        // negative i32 into Err(MakeSyscallError).  Real errnos are
        // -1..=-255; treat anything more negative as a high user_addr.
        let new_host = match ret {
            Ok(addr) if addr >= 0 => addr as u32 as u64,
            Err(grate_rs::GrateError::MakeSyscallError(n)) if n <= -256 => n as u32 as u64,
            _ => return Err(grate_rs::constants::error::ENOMEM),
        };

        // Copy live bytes (up to the logical file size, not the old
        // capacity) into the new region.  Anonymous mappings are
        // zero-initialized so the tail past the live bytes is
        // already zero — no fill needed.
        let live_bytes = self.nodes[node_idx].total_size.min(current_cap);
        if current_host != 0 && live_bytes > 0 {
            // SAFETY: both regions are owned by this grate and non-
            // overlapping; sizes are bounded by current_cap / new_cap.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    current_host as *const u8,
                    new_host as *mut u8,
                    live_bytes,
                );
            }
        }

        // Release the old region via threei.
        if current_host != 0 && current_cap > 0 {
            let _ = make_threei_call(
                SYS_MUNMAP as u32,
                0,
                thiscage,
                thiscage,
                current_host,
                0,
                current_cap as u64,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            );
        }

        if let NodeInfo::RegMapped {
            host_addr,
            capacity,
            ..
        } = &mut self.nodes[node_idx].info
        {
            *host_addr = new_host;
            *capacity = new_cap;
        }
        Ok(())
    }

    /// Promote a plain `Reg` node (chunk-chain storage) to a
    /// `RegMapped` node (host-backed contiguous storage).  Called
    /// lazily on the first `mmap()` that targets the file: chunked
    /// storage isn't aliasable into a cage's vmmap, so we drain the
    /// chunks into a fresh host mapping at that point.
    ///
    /// The node's `total_size` is preserved; the chunk chain is
    /// reclaimed; `node_type` and `info` both flip to the mapped
    /// variant.  Subsequent reads / writes hit the host-mapped fast
    /// paths in `read_from_node` / `write_to_node`.
    ///
    /// Returns Ok(()) on success, or:
    ///   - `EINVAL` if the node isn't `Reg`.
    ///   - `ENOMEM` if the host mmap failed.
    fn promote_to_mapped(&mut self, node_idx: usize) -> Result<(), i32> {
        // Must currently be plain Reg.
        let head = match &self.nodes[node_idx].info {
            NodeInfo::Reg { head, .. } => *head,
            NodeInfo::RegMapped { .. } => return Ok(()), // already promoted
            _ => return Err(grate_rs::constants::error::EINVAL),
        };

        let size = self.nodes[node_idx].total_size;

        // Allocate the host region.  Mirror the same shape as
        // ensure_mapped_backing's allocator so the page-rounding and
        // flags are consistent.
        const PAGE_SIZE: usize = 4096;
        let cap = ((size.max(1) + PAGE_SIZE - 1) / PAGE_SIZE) * PAGE_SIZE;
        let thiscage = getcageid();
        let ret = make_threei_call(
            SYS_MMAP as u32,
            0,
            thiscage,
            thiscage,
            0,
            0,
            cap as u64,
            0,
            (PROT_READ | PROT_WRITE) as u64,
            0,
            (MAP_ANON | MAP_SHARED) as u64,
            0,
            u64::MAX,
            0,
            0,
            0,
            0,
        );
        // See ensure_mapped_backing for why we accept large negative
        // i32 returns as valid wasm user-space addresses.
        let host_addr = match ret {
            Ok(addr) if addr >= 0 => addr as u32 as u64,
            Err(grate_rs::GrateError::MakeSyscallError(n)) if n <= -256 => n as u32 as u64,
            _ => return Err(grate_rs::constants::error::ENOMEM),
        };

        // Drain the chunk chain into the host mapping in file order.
        let mut chunk_idx = head;
        let mut dst_offset: usize = 0;
        while let Some(ci) = chunk_idx {
            let used = self.chunks[ci].used;
            if used > 0 {
                let dst = (host_addr as *mut u8).wrapping_add(dst_offset);
                // SAFETY: dst_offset + used <= total_size <= cap.
                unsafe {
                    core::ptr::copy_nonoverlapping(self.chunks[ci].data.as_ptr(), dst, used);
                }
                dst_offset += used;
            }
            chunk_idx = self.chunks[ci].next;
        }

        // Reclaim the chunks now that their contents are in the host
        // region.
        self.reclaim_chunk_chain(head);

        // Flip the variant + node_type.  Stat / dirent code already
        // treats RegMapped as a regular file for external purposes.
        self.nodes[node_idx].info = NodeInfo::RegMapped {
            host_addr,
            capacity: cap,
            mmap_refs: 0,
        };
        self.nodes[node_idx].node_type = NodeType::RegMapped;

        Ok(())
    }

    /// Release the host mapping for a `RegMapped` node.  Called when
    /// the node is being reclaimed (final close after unlink) so the
    /// host pages don't leak.  Panics if any cage still has it
    /// mapped (`mmap_refs > 0`) — that's a refcount bug the caller
    /// must fix; we deliberately don't silently leak.
    fn free_mapped_backing(&mut self, node_idx: usize) {
        let (host, cap) = match &mut self.nodes[node_idx].info {
            NodeInfo::RegMapped {
                host_addr,
                capacity,
                mmap_refs,
            } => {
                debug_assert_eq!(
                    *mmap_refs, 0,
                    "free_mapped_backing called with live mmap_refs={}",
                    *mmap_refs
                );
                let h = *host_addr;
                let c = *capacity;
                *host_addr = 0;
                *capacity = 0;
                (h, c)
            }
            _ => return,
        };
        if host != 0 && cap > 0 {
            // Release the host mapping via threei.
            let thiscage = getcageid();
            let _ = make_threei_call(
                SYS_MUNMAP as u32,
                0,
                thiscage,
                thiscage,
                host,
                0,
                cap as u64,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            );
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
            } else {
                self.nodes[entry_idx].link_target().unwrap_or(entry_idx)
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

            if matches!(
                self.nodes[idx].node_type,
                NodeType::Reg | NodeType::RegMapped
            ) && (flags & O_TRUNC) != 0
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

    /// Read bytes from a regular file starting at the given byte offset.
    /// For plain `Reg` nodes this walks the chunk chain; for `RegMapped`
    /// nodes with no active cage mapping it reads the host backing directly.
    /// Returns the number of bytes actually read.
    fn read_from_node(&self, node_idx: usize, offset: usize, buf: &mut [u8]) -> usize {
        let node = &self.nodes[node_idx];
        if offset >= node.total_size {
            return 0;
        }

        let count = buf.len().min(node.total_size - offset);

        let read = match &node.info {
            NodeInfo::Reg { head, .. } => {
                let mut chunk_idx = *head;
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
                    buf[read..read + to_copy].copy_from_slice(
                        &self.chunks[ci].data[local_offset..local_offset + to_copy],
                    );
                    read += to_copy;
                    local_offset = 0;
                    chunk_idx = self.chunks[ci].next;
                }
                read
            }
            NodeInfo::RegMapped {
                host_addr,
                capacity,
                ..
            } => {
                if *host_addr == 0 || offset >= *capacity {
                    return 0;
                }
                let readable = count.min(capacity.saturating_sub(offset));
                // SAFETY: the RegMapped host backing is an owned readable
                // mapping of at least `capacity` bytes.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        (*host_addr as *const u8).add(offset),
                        buf.as_mut_ptr(),
                        readable,
                    );
                }
                readable
            }
            _ => return 0,
        };

        // Overlay bytes from live cage mappings only for the file range
        // those mappings actually cover.  Mapping writes are synced back
        // to backing storage on munmap/exit, so while a mapping is live
        // it is the freshest source for its own covered byte range.
        let thiscage = getcageid();
        for (owner_cage, owner_uaddr, _map_len, map_offset, start, end) in
            self.active_mapping_overlaps(node_idx, offset, read)
        {
            let buf_offset = start - offset;
            let map_delta = start - map_offset;
            let copy_len = end - start;
            let _ = copy_data_between_cages(
                thiscage,
                thiscage,
                owner_uaddr + map_delta as u64,
                owner_cage,
                buf.as_mut_ptr().wrapping_add(buf_offset) as u64,
                thiscage,
                copy_len as u64,
                0,
            );
        }

        read
    }

    /// Write bytes to a regular file starting at the given byte offset.
    /// Plain `Reg` nodes use chunk storage; `RegMapped` nodes with no active
    /// cage mapping write into the host backing directly.
    fn write_to_node(&mut self, node_idx: usize, offset: usize, buf: &[u8]) -> usize {
        if buf.is_empty() {
            return 0;
        }

        if matches!(self.nodes[node_idx].info, NodeInfo::RegMapped { .. }) {
            let end = offset + buf.len();
            if self.ensure_mapped_backing(node_idx, end).is_err() {
                return 0;
            }
            let host_addr = match &self.nodes[node_idx].info {
                NodeInfo::RegMapped { host_addr, .. } => *host_addr,
                _ => return 0,
            };
            if host_addr == 0 {
                return 0;
            }
            // SAFETY: ensure_mapped_backing guarantees the host mapping covers
            // `offset..end`; `buf` is valid for `buf.len()` bytes.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    buf.as_ptr(),
                    (host_addr as *mut u8).add(offset),
                    buf.len(),
                );
            }
            if end > self.nodes[node_idx].total_size {
                self.nodes[node_idx].total_size = end;
            }
            self.mirror_write_to_active_mappings(node_idx, offset, buf);
            return buf.len();
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

            // Write offset is past this whole chunk: mark it fully
            // zero-used (alloc_chunk gave us zeroed bytes) and skip
            // to the next chunk.  Needed when growing a file past
            // multiple chunk boundaries from empty — e.g. ftruncate
            // a fresh file to 4096 writes 1 byte at offset 4095.
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

        if written > 0 {
            self.mirror_write_to_active_mappings(node_idx, offset, &buf[..written]);
        }

        written
    }

    fn truncate_node(&mut self, node_idx: usize, new_size: usize) {
        let old_size = self.nodes[node_idx].total_size;

        if new_size == old_size {
            return;
        }

        if matches!(self.nodes[node_idx].info, NodeInfo::RegMapped { .. }) {
            if new_size > old_size {
                if self.ensure_mapped_backing(node_idx, new_size).is_err() {
                    return;
                }
            }

            let (host_addr, capacity) = match &self.nodes[node_idx].info {
                NodeInfo::RegMapped {
                    host_addr,
                    capacity,
                    ..
                } => (*host_addr, *capacity),
                _ => return,
            };

            if host_addr != 0 {
                if new_size > old_size {
                    let zero_len = new_size - old_size;
                    if old_size < capacity {
                        let zero_len = zero_len.min(capacity - old_size);
                        // SAFETY: old_size..old_size+zero_len is inside the
                        // RegMapped host backing.
                        unsafe {
                            core::ptr::write_bytes(
                                (host_addr as *mut u8).add(old_size),
                                0,
                                zero_len,
                            );
                        }
                    }
                } else if new_size < old_size && new_size < capacity {
                    let zero_len = (old_size - new_size).min(capacity - new_size);
                    // SAFETY: new_size..new_size+zero_len is inside the
                    // RegMapped host backing.
                    unsafe {
                        core::ptr::write_bytes((host_addr as *mut u8).add(new_size), 0, zero_len);
                    }
                }
            }

            self.nodes[node_idx].total_size = new_size;

            if new_size < old_size {
                let zero_len = old_size - new_size;
                let zeros = vec![0u8; zero_len];
                self.mirror_write_to_active_mappings(node_idx, new_size, &zeros);
            }
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
        while let NodeInfo::Lnk { target } = &self.nodes[idx].info {
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

        // Also inherit mmap_tracking entries.  Linux fork copies the
        // parent's mappings into the child at the same uaddrs, and for
        // MAP_ANON | MAP_SHARED (which is what imfs::mmap forwards) the
        // kernel pages are shared between parent and child.  Carrying
        // the tracking entry over means a later `imfs::mmap()` call in
        // the child can recognize the inherited mapping and hand back
        // the same uaddr instead of forwarding a fresh anonymous mmap
        // that would land on a non-shared region.
        let inherited: Vec<((u64, u64), (usize, usize, usize))> = self
            .mmap_tracking
            .iter()
            .filter(|((c, _), _)| *c == parent_cage)
            .map(|(k, v)| (*k, *v))
            .collect();
        for ((_, uaddr), value) in inherited {
            self.mmap_tracking.insert((child_cage, uaddr), value);
            self.increment_mmap_ref(value.0);
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
        while let NodeInfo::Lnk { target } = &self.nodes[node_idx].info {
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
        self.stat_resolved_path(&norm_path, statbuf)
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

    pub fn statat(&mut self, cage_id: u64, dirfd: i32, path: &str, statbuf: &mut stat) -> i32 {
        let norm_path = match self.normalize_path_at(cage_id, dirfd, path) {
            Ok(path) => path,
            Err(e) => return e,
        };
        self.stat_resolved_path(&norm_path, statbuf)
    }

    fn stat_resolved_path(&mut self, norm_path: &str, statbuf: &mut stat) -> i32 {
        let node_idx = match self.resolve_path(&norm_path, true) {
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
                self.try_reclaim_doomed_node(node_idx);
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
            NodeInfo::Reg { .. } | NodeInfo::RegMapped { .. } => {}
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
            NodeInfo::Reg { .. } | NodeInfo::RegMapped { .. } => {}
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
            NodeInfo::Reg { .. } | NodeInfo::RegMapped { .. } => {}
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
            NodeInfo::Reg { .. } | NodeInfo::RegMapped { .. } => {}
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
            NodeInfo::Reg { .. } | NodeInfo::RegMapped { .. } => {}
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
        self.nodes[node_idx].doomed = true;

        self.try_reclaim_doomed_node(node_idx);

        0
    }

    /// link: (int cage_id, const char *oldpath, const char *newpath) {
    pub fn link(&mut self, cage_id: u64, oldpath: &str, newpath: &str) -> i32 {
        // Ensure old path exists.
        let norm_oldpath = self.normalize_path_for_cage(cage_id, oldpath);
        let old_idx = match self.resolve_path(&norm_oldpath, true) {
            Ok(idx) => idx,
            Err(e) => return e,
        };

        if self.nodes[old_idx].node_type == NodeType::Dir {
            return -1; // EPERM
        }

        // Ensure newpath does not exist.
        let norm_newpath = self.normalize_path_for_cage(cage_id, newpath);
        match self.resolve_path(&norm_newpath, false) {
            Ok(_) => return -17, // EEXIST
            Err(-2) => {}
            Err(e) => return e,
        };

        // open(O_CREAT) behaviour.
        let (parent_idx, filename) = match self.resolve_parent_and_name(&norm_newpath) {
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
        self.update_mtime(parent_idx);
        self.update_ctime(parent_idx);
        self.update_ctime(old_idx);
        self.update_mtime(new_idx);
        self.update_ctime(new_idx);

        0
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
            NodeType::Reg | NodeType::RegMapped => {}
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
            NodeType::Reg | NodeType::RegMapped => {}
            NodeType::Dir => return -21, // EISDIR
            _ => return -22,             // EINVAL
        }

        self.truncate_node(node_idx, length as usize);
        self.update_mtime(node_idx);
        self.update_ctime(node_idx);

        0
    }

    /// mmap: map an imfs file into the calling cage's vmmap.
    ///
    /// Strategy: forward the call to RawPOSIX as a plain anonymous
    /// MAP_SHARED mapping (the runtime picks a free uaddr in the
    /// calling cage's vmmap), then seed the resulting region with the
    /// file's current contents.  The mapping is recorded in
    /// `mmap_tracking` and becomes the file's live view: subsequent
    /// fd reads/writes route through it via `copy_data_between_cages`.
    ///
    /// Cross-cage sharing comes from fork-inheritance of MAP_ANON |
    /// MAP_SHARED — parent and child see the same kernel pages and
    /// each other's writes, which covers the postgres dynshmem
    /// pattern.  Unrelated cages mapping the same file each get their
    /// own region (no automatic sharing across non-fork lineages).
    ///
    /// Returns the cage uaddr of the new mapping, or a negative errno.
    pub fn mmap(
        &mut self,
        cage_id: u64,
        _addr: u64,
        len: usize,
        prot: i32,
        flags: i32,
        fd: u64,
        offset: u64,
    ) -> i32 {
        // Anonymous mappings aren't ours — bounce so the handler
        // forwards SYS_MMAP through unchanged.
        if (flags & MAP_ANON) != 0 || fd == u64::MAX {
            return -(grate_rs::constants::error::ENOSYS as i32);
        }

        // Only handle fds imfs owns.  Anything else (kernel fd routed
        // through, a different grate's fd, no fdtable entry) bounces
        // to the next layer.
        let entry = match fdtables::translate_virtual_fd(cage_id, fd) {
            Ok(e) if e.fdkind == IMFS_FDKIND => e,
            _ => return -(grate_rs::constants::error::ENOSYS as i32),
        };
        let node_idx = entry.underfd as usize;
        if node_idx >= self.nodes.len() {
            return -9; // EBADF
        }
        match self.nodes[node_idx].node_type {
            NodeType::Reg | NodeType::RegMapped => {}
            _ => return -(grate_rs::constants::error::ENODEV as i32),
        }

        // If this cage already has an mmap tracked for this node (e.g.
        // inherited from a fork parent), hand back the same uaddr.
        // The cage's vmmap already holds the MAP_ANON | MAP_SHARED
        // region there, and Linux fork makes those pages shared with
        // whichever ancestor / sibling already wrote into them — so
        // the caller's memcpy lands on the same kernel pages everyone
        // else sees.  Postgres-DSM "worker attaches to existing
        // segment by name" pattern.
        let inherited = self
            .mmap_tracking
            .iter()
            .find_map(|(&(c, u), &(n, _len, _offset))| {
                if c == cage_id && n == node_idx {
                    Some(u)
                } else {
                    None
                }
            });
        if let Some(uaddr) = inherited {
            return uaddr as i32;
        }

        if self.promote_to_mapped(node_idx).is_err() {
            return -(grate_rs::constants::error::ENOMEM as i32);
        }
        if self
            .ensure_mapped_backing(node_idx, (offset as usize).saturating_add(len))
            .is_err()
        {
            return -(grate_rs::constants::error::EBUSY as i32);
        }

        // Forward to RawPOSIX as MAP_ANON | MAP_SHARED (no MAP_FIXED,
        // no GRATE_MEMORY_FLAG).  The runtime picks a free uaddr in
        // the calling cage's vmmap.  fd=-1 because we're not
        // file-backing through RawPOSIX; we'll seed the contents
        // ourselves below.
        let thiscage = getcageid();
        let cage_flags = MAP_ANON | MAP_SHARED;
        let ret = make_threei_call(
            SYS_MMAP as u32,
            0,
            thiscage,
            cage_id,
            0,
            0, // addr: NULL hint
            len as u64,
            0,
            prot as u64,
            0,
            cage_flags as u64,
            0,
            u64::MAX,
            0, // fd = -1
            0,
            0, // offset = 0
            0,
        );
        // mmap returns wasm uaddrs which can have bit 31 set.  Real
        // errnos live in (-256, 0); anything more negative is a
        // valid high uaddr that grate-rs collapsed into Err.
        let mapped = match ret {
            Ok(v) if v >= 0 => v as u32 as u64,
            Ok(v) => return v,
            Err(grate_rs::GrateError::MakeSyscallError(n)) if n <= -256 => n as u32 as u64,
            Err(grate_rs::GrateError::MakeSyscallError(n)) => return n,
            Err(_) => return -(grate_rs::constants::error::ENOMEM as i32),
        };

        // Seed the new region with the file's current bytes.
        let total_size = self.nodes[node_idx].total_size;
        let copy_len = total_size.saturating_sub(offset as usize).min(len);
        if copy_len > 0 {
            let mut tmp = vec![0u8; copy_len];
            let _ = self.read_from_node(node_idx, offset as usize, &mut tmp);
            let _ = copy_data_between_cages(
                thiscage,
                cage_id,
                tmp.as_ptr() as u64,
                thiscage,
                mapped,
                cage_id,
                copy_len as u64,
                0,
            );
        }

        // Record the mapping.  Routes future fd I/O through it.
        self.mmap_tracking
            .insert((cage_id, mapped), (node_idx, len, offset as usize));
        self.increment_mmap_ref(node_idx);

        mapped as i32
    }

    /// Find any live mmap for `node_idx`, returning `(cage, uaddr)`.
    /// First hit wins — for fork-inherited mappings (parent + child
    /// both have entries pointing at the same kernel pages) it doesn't
    /// matter which one we pick; for distinct cages mapping the same
    /// file independently, we'd see only one (this is the no-sharing
    /// case noted in `mmap`'s doc).
    fn find_active_mapping(&self, node_idx: usize) -> Option<(u64, u64)> {
        self.mmap_tracking
            .iter()
            .find_map(|(&(cage, uaddr), &(nidx, _len, _offset))| {
                if nidx == node_idx {
                    Some((cage, uaddr))
                } else {
                    None
                }
            })
    }

    fn active_mapping_overlaps(
        &self,
        node_idx: usize,
        offset: usize,
        len: usize,
    ) -> Vec<(u64, u64, usize, usize, usize, usize)> {
        let end = offset.saturating_add(len);
        self.mmap_tracking
            .iter()
            .filter_map(|(&(cage, uaddr), &(nidx, map_len, map_offset))| {
                if nidx != node_idx {
                    return None;
                }
                let map_end = map_offset.saturating_add(map_len);
                let start = offset.max(map_offset);
                let overlap_end = end.min(map_end);
                if start < overlap_end {
                    Some((cage, uaddr, map_len, map_offset, start, overlap_end))
                } else {
                    None
                }
            })
            .collect()
    }

    fn mirror_write_to_active_mappings(&self, node_idx: usize, offset: usize, buf: &[u8]) {
        if buf.is_empty() {
            return;
        }

        let thiscage = getcageid();
        for (owner_cage, owner_uaddr, _map_len, map_offset, start, end) in
            self.active_mapping_overlaps(node_idx, offset, buf.len())
        {
            let buf_offset = start - offset;
            let map_delta = start - map_offset;
            let copy_len = end - start;
            let _ = copy_data_between_cages(
                thiscage,
                owner_cage,
                buf.as_ptr().wrapping_add(buf_offset) as u64,
                thiscage,
                owner_uaddr + map_delta as u64,
                owner_cage,
                copy_len as u64,
                0,
            );
        }
    }

    fn increment_mmap_ref(&mut self, node_idx: usize) {
        if let NodeInfo::RegMapped { mmap_refs, .. } = &mut self.nodes[node_idx].info {
            *mmap_refs = mmap_refs.saturating_add(1);
        }
    }

    fn decrement_mmap_ref(&mut self, node_idx: usize) {
        if let NodeInfo::RegMapped { mmap_refs, .. } = &mut self.nodes[node_idx].info {
            debug_assert!(*mmap_refs > 0, "mmap_refs underflow for node {}", node_idx);
            *mmap_refs = mmap_refs.saturating_sub(1);
        }
    }

    /// munmap: drop a cage-side mapping previously created by
    /// `mmap`.  Before tearing down the cage's vmmap entry, sync the
    /// mapping's current contents back into the file's chunk storage
    /// so future fd reads (after no mapping remains) see the latest
    /// bytes.  For untracked addresses we just forward to RawPOSIX.
    pub fn munmap(&mut self, cage_id: u64, addr: u64, len: usize) -> i32 {
        // mmap stored entries keyed by the wasm uaddr returned from
        // SYS_MMAP, but by the time munmap reaches us the runtime has
        // already translated the pointer arg from that uaddr to the
        // corresponding host sysaddr — so direct lookup by
        // (cage, addr) misses.  Fall back to matching by (cage, len),
        // which is unique for our use (each cage holds at most one
        // live mapping per node).
        let mut tracked_addr = addr;
        let mut tracked = self.mmap_tracking.remove(&(cage_id, addr));
        if tracked.is_none() {
            let candidate = self
                .mmap_tracking
                .iter()
                .find(|((c, _), (_, l, _))| *c == cage_id && *l == len)
                .map(|(k, _)| *k);
            if let Some(k) = candidate {
                tracked_addr = k.1;
                tracked = self.mmap_tracking.remove(&k);
            }
        }

        // If we owned this mapping, drop its live ref.  If it was the
        // last live mapping for the node, copy its bytes back into the
        // file's persistent storage so future fd reads and later mmaps
        // see whatever the cage wrote through the pointer view.
        if let Some((node_idx, map_len, map_offset)) = tracked {
            self.decrement_mmap_ref(node_idx);
            let still_mapped = self.find_active_mapping(node_idx).is_some();
            if !still_mapped {
                self.sync_mapping_to_storage(node_idx, cage_id, tracked_addr, map_len, map_offset);
            }
            self.try_reclaim_doomed_node(node_idx);
        }

        // Always forward to RawPOSIX so the cage's vmmap entry is
        // actually torn down.
        let thiscage = getcageid();
        let ret = make_threei_call(
            SYS_MUNMAP as u32,
            0,
            thiscage,
            cage_id,
            addr,
            0,
            len as u64,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        );

        match ret {
            Ok(v) => v,
            Err(grate_rs::GrateError::MakeSyscallError(n)) => n,
            Err(_) => -22,
        }
    }

    /// Copy `len` bytes from `(cage, uaddr)` back into `node_idx`'s
    /// backing storage.  Called on the last munmap of a node to make
    /// persistent file state reflect whatever the cage wrote through
    /// its mapping.
    fn sync_mapping_to_storage(
        &mut self,
        node_idx: usize,
        cage: u64,
        uaddr: u64,
        len: usize,
        file_offset: usize,
    ) {
        let size = self.nodes[node_idx].total_size;
        let copy_len = size.saturating_sub(file_offset).min(len);
        if copy_len == 0 {
            return;
        }
        let thiscage = getcageid();
        let mut tmp = vec![0u8; copy_len];
        let _ = copy_data_between_cages(
            thiscage,
            thiscage,
            uaddr,
            cage,
            tmp.as_mut_ptr() as u64,
            thiscage,
            copy_len as u64,
            0,
        );

        if let NodeInfo::RegMapped {
            host_addr,
            capacity,
            ..
        } = &self.nodes[node_idx].info
        {
            if *host_addr == 0 {
                return;
            }
            if file_offset >= *capacity {
                return;
            }
            let writable = copy_len.min(*capacity - file_offset);
            // SAFETY: host_addr points to the RegMapped backing and `writable`
            // is bounded by its capacity.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    tmp.as_ptr(),
                    (*host_addr as *mut u8).add(file_offset),
                    writable,
                );
            }
            return;
        }

        // Walk chunks and overwrite their bytes.  We can't go through
        // `write_to_node` because it would short-circuit back into the
        // mapping (which we've already removed from tracking, but the
        // chunk walk is simpler regardless).
        let mut chunk_idx = match &self.nodes[node_idx].info {
            NodeInfo::Reg { head, .. } => *head,
            _ => return,
        };
        let mut copied = 0;
        let mut local_offset = file_offset;
        while let Some(ci) = chunk_idx {
            if local_offset < CHUNK_SIZE {
                break;
            }
            local_offset -= CHUNK_SIZE;
            chunk_idx = self.chunks[ci].next;
        }
        while copied < copy_len {
            let ci = match chunk_idx {
                Some(ci) => ci,
                None => break,
            };
            let available = CHUNK_SIZE - local_offset;
            let to_copy = (copy_len - copied).min(available);
            self.chunks[ci].data[local_offset..local_offset + to_copy]
                .copy_from_slice(&tmp[copied..copied + to_copy]);
            if local_offset + to_copy > self.chunks[ci].used {
                self.chunks[ci].used = local_offset + to_copy;
            }
            copied += to_copy;
            local_offset = 0;
            chunk_idx = self.chunks[ci].next;
        }
    }

    /// Drop all RegMapped mappings owned by `cage_id`.  Called from
    /// the grate's teardown hook so a cage that exits without
    /// explicit `munmap`s doesn't leave the underlying RegMapped
    /// node's `mmap_refs` stuck at a positive value, which would
    /// otherwise pin the host region and reject any future grow.
    ///
    /// We don't forward `SYS_MUNMAP` here; the exit path is about to
    /// tear down the cage's vmmap.  We only update IMFS bookkeeping,
    /// and if a removed mapping was the last mapping for a node, we
    /// make a best-effort sync before forwarding the exit syscall.
    pub fn cage_exit(&mut self, cage_id: u64) {
        let removed: Vec<(u64, usize, usize, usize)> = self
            .mmap_tracking
            .iter()
            .filter_map(|(&(cage, uaddr), &(node_idx, len, file_offset))| {
                if cage == cage_id {
                    Some((uaddr, node_idx, len, file_offset))
                } else {
                    None
                }
            })
            .collect();

        self.mmap_tracking
            .retain(|(cage, _addr), _| *cage != cage_id);

        for (uaddr, node_idx, len, file_offset) in removed {
            self.decrement_mmap_ref(node_idx);
            if self.find_active_mapping(node_idx).is_none() {
                self.sync_mapping_to_storage(node_idx, cage_id, uaddr, len, file_offset);
            }
            self.try_reclaim_doomed_node(node_idx);
        }

        // Clean up the per-cage cwd and any leftover fd offsets too.
        self.cwd_info.remove(&cage_id);
        self.fd_info.retain(|(c, _fd), _| *c != cage_id);
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
        self.nodes[dot_idx].info = NodeInfo::Lnk { target: dir_idx };
        self.add_child(dir_idx, dot_idx);

        let dotdot_idx = self.create_node("..", NodeType::Lnk, 0);
        self.nodes[dotdot_idx].info = NodeInfo::Lnk { target: parent_idx };
        self.add_child(dir_idx, dotdot_idx);
        self.update_mtime(parent_idx);
        self.update_ctime(parent_idx);
        self.update_mtime(dir_idx);
        self.update_ctime(dir_idx);

        0
    }
}
