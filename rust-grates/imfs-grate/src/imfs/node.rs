//! IMFS node and chunk types.
//!
//! The filesystem is a tree of Nodes (directories, regular files, symlinks, pipes).
//! Regular file data is stored in linked-list chains of 1024-byte Chunks.
//! All nodes and chunks live in arena-style Vec storage and are referenced by index.

pub const CHUNK_SIZE: usize = 1024;
pub const MAX_NODE_NAME: usize = 65;
pub const MAX_NODES: usize = 1024;

// Stub constants for stat results.
pub const GET_UID: u32 = 501;
pub const GET_GID: u32 = 20;
pub const _GET_DEV: u64 = 1;

/// The type of a filesystem node.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum NodeType {
    /// Regular file (chunk-chain storage).
    Reg,
    /// Regular file with host-mmap'd contiguous backing — for files
    /// that will be `mmap`'d into one or more cages.  Stat reports
    /// this as a regular file (`S_IFREG`); the distinction is purely
    /// about how imfs stores the bytes.
    RegMapped,
    /// Directory.
    Dir,
    /// Symbolic link.
    Lnk,
    /// Pipe.
    #[allow(unused)]
    Pip,
    /// Free / unallocated slot.
    Free,
}

/// A directory entry: a name and the index of the node it points to.
#[derive(Clone, Debug)]
pub struct DirEntry {
    pub name: String,
    pub node_idx: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct NodeTime {
    pub secs: u64,
    pub nanos: u64,
}

impl NodeTime {
    pub fn now() -> Self {
        Self { secs: 0, nanos: 0 }
    }

    pub fn as_stat_pair(self) -> [u64; 2] {
        [self.secs, self.nanos]
    }
}

/// Type-specific data for a node.
#[derive(Clone, Debug)]
pub enum NodeInfo {
    /// Regular file: linked list of chunks.
    Reg {
        head: Option<usize>,
        tail: Option<usize>,
    },
    /// Regular file backed by a single contiguous host page range.
    ///
    /// Distinct from `Reg`: the storage isn't a chunk chain in the
    /// grate's arena, it's an actual host mmap'd region.  Created
    /// when the file is expected to be mapped into a cage (e.g.
    /// path-based config like `/pg_dynshmem/*`, or anything that
    /// matches a "needs mmap" rule in the routing layer).
    ///
    /// The mapping is allocated by the imfs grate via
    /// `SYS_MMAP(NULL, capacity, PROT_READ|PROT_WRITE,
    ///           MAP_ANONYMOUS|MAP_SHARED, -1, 0)` so the backing is
    /// real host kernel pages.  When a cage `mmap`s the file, the
    /// grate routes the call back through
    /// `SYS_MMAP(host_addr, len, prot,
    ///           MAP_ANONYMOUS|MAP_SHARED|MAP_FIXED, -1, 0)` so the
    /// cage's vmmap aliases those same host pages — meaning multiple
    /// cages mapping the same file share writes (real MAP_SHARED
    /// semantics, not a per-cage copy).
    ///
    /// `host_addr`: base of the host mapping (0 if not yet allocated).
    /// `capacity`: size of the mapping in bytes; the file's logical
    /// length (`Node::total_size`) is `<= capacity`.
    /// `mmap_refs`: number of live cage mappings of this file.  While
    /// > 0 the region is pinned (cannot be remapped to a different
    /// host address).
    RegMapped {
        host_addr: u64,
        capacity: usize,
        mmap_refs: u32,
    },
    /// Directory: list of child entries.
    Dir { children: Vec<DirEntry> },
    /// Symbolic/hard link: index of the target node.
    Lnk { target: usize },
    /// Pipe (limited implementation).
    Pip {
        data: Vec<u8>,
        readers: u32,
        writers: u32,
    },
    /// Free slot.
    Free,
}

/// A filesystem node.
#[derive(Clone, Debug)]
pub struct Node {
    pub node_type: NodeType,

    #[allow(unused)]
    pub index: usize,

    pub total_size: usize,
    pub name: String,
    pub parent_idx: usize,
    /// Number of open file descriptions referencing this node.
    pub in_use: u32,
    /// Marked for deletion once all references are closed.
    pub doomed: bool,
    pub mode: u32,

    #[allow(unused)]
    pub owner: u32,

    #[allow(unused)]
    pub group: u32,

    pub info: NodeInfo,

    pub ctime: NodeTime,
    pub atime: NodeTime,
    pub mtime: NodeTime,
}

impl Node {
    /// Create a new node with the given name, type, and permissions.
    pub fn new(index: usize, name: &str, node_type: NodeType, mode: u32) -> Self {
        let mode_bits = match node_type {
            NodeType::Reg | NodeType::RegMapped => 0o100000 | (mode & 0o777), // S_IFREG
            NodeType::Dir => 0o040000 | (mode & 0o777),                       // S_IFDIR
            NodeType::Lnk => 0o120000 | (mode & 0o777),                       // S_IFLNK
            _ => mode & 0o777,
        };

        let info = match node_type {
            NodeType::Reg => NodeInfo::Reg {
                head: None,
                tail: None,
            },
            // RegMapped starts with no host mapping; it's allocated
            // lazily by `Filesystem::ensure_mapped_backing` on the
            // first write or ftruncate so we don't pay an mmap
            // syscall on opens for files that may never grow.
            NodeType::RegMapped => NodeInfo::RegMapped {
                host_addr: 0,
                capacity: 0,
                mmap_refs: 0,
            },
            NodeType::Dir => NodeInfo::Dir {
                children: Vec::new(),
            },
            NodeType::Lnk => NodeInfo::Lnk { target: 0 },
            NodeType::Pip => NodeInfo::Pip {
                data: Vec::new(),
                readers: 0,
                writers: 0,
            },
            NodeType::Free => NodeInfo::Free,
        };

        let now = NodeTime::now();

        Node {
            node_type,
            index,
            total_size: 0,
            name: name.to_string(),
            parent_idx: 0,
            in_use: 0,
            doomed: false,
            mode: mode_bits,
            owner: GET_UID,
            group: GET_GID,
            info,
            atime: now,
            ctime: now,
            mtime: now,
        }
    }

    /// Get mutable children of a directory node.
    pub fn children_mut(&mut self) -> &mut Vec<DirEntry> {
        match &mut self.info {
            NodeInfo::Dir { children } => children,
            _ => panic!("not a directory"),
        }
    }

    /// Get children of a directory node.
    pub fn children(&self) -> &Vec<DirEntry> {
        match &self.info {
            NodeInfo::Dir { children } => children,
            _ => panic!("not a directory"),
        }
    }

    /// Get the link target index of a link node.
    pub fn link_target(&self) -> Option<usize> {
        match &self.info {
            NodeInfo::Lnk { target } => Some(*target),
            _ => None,
        }
    }
}

/// A 1024-byte chunk of file data, part of a linked list.
#[derive(Clone)]
pub struct Chunk {
    pub data: [u8; CHUNK_SIZE],
    pub used: usize,
    /// Index of the next chunk in the chain, or None.
    pub next: Option<usize>,
}

impl Chunk {
    pub fn new() -> Self {
        Chunk {
            data: [0u8; CHUNK_SIZE],
            used: 0,
            next: None,
        }
    }
}
