//! IMFS node and chunk types.
//!
//! The filesystem is a tree of Nodes (directories, regular files, symlinks, pipes).
//! Regular file data is stored in linked-list chains of 1024-byte Chunks.
//! All nodes and chunks live in arena-style Vec storage and are referenced by index.

pub const CHUNK_SIZE: usize = 1024;
pub const MAX_NODE_NAME: usize = 65;
pub const MAX_NODES: usize = 1024;
pub const MAX_DEPTH: usize = 10;

// Stub constants for stat results.
pub const GET_UID: u32 = 501;
pub const GET_GID: u32 = 20;
pub const GET_DEV: u64 = 1;

/// The type of a filesystem node.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum NodeType {
    /// Regular file.
    Reg,
    /// Directory.
    Dir,
    /// Symbolic link.
    Lnk,
    /// Pipe.
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

/// Type-specific data for a node.
#[derive(Clone, Debug)]
pub enum NodeInfo {
    /// Regular file: linked list of chunks.
    Reg {
        head: Option<usize>,
        tail: Option<usize>,
    },
    /// Directory: list of child entries.
    Dir {
        children: Vec<DirEntry>,
    },
    /// Symbolic/hard link: index of the target node.
    Lnk {
        target: usize,
    },
    /// Pipe (limited implementation).
    Pip {
        data: Vec<u8>,
        offset: usize,
    },
    /// Free slot.
    Free,
}

/// A filesystem node.
#[derive(Clone, Debug)]
pub struct Node {
    pub node_type: NodeType,
    pub index: usize,
    pub total_size: usize,
    pub name: String,
    pub parent_idx: usize,
    /// Number of open file descriptions referencing this node.
    pub in_use: u32,
    /// Marked for deletion once all references are closed.
    pub doomed: bool,
    pub mode: u32,
    pub owner: u32,
    pub group: u32,
    pub info: NodeInfo,
}

impl Node {
    /// Create a new node with the given name, type, and permissions.
    pub fn new(index: usize, name: &str, node_type: NodeType, mode: u32) -> Self {
        let mode_bits = match node_type {
            NodeType::Reg => 0o100000 | (mode & 0o777), // S_IFREG
            NodeType::Dir => 0o040000 | (mode & 0o777), // S_IFDIR
            NodeType::Lnk => 0o120000 | (mode & 0o777), // S_IFLNK
            _ => mode & 0o777,
        };

        let info = match node_type {
            NodeType::Reg => NodeInfo::Reg { head: None, tail: None },
            NodeType::Dir => NodeInfo::Dir { children: Vec::new() },
            NodeType::Lnk => NodeInfo::Lnk { target: 0 },
            NodeType::Pip => NodeInfo::Pip { data: vec![0u8; CHUNK_SIZE], offset: 0 },
            NodeType::Free => NodeInfo::Free,
        };

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
        }
    }

    /// Get the children of a directory node. Panics if not a directory.
    pub fn children(&self) -> &[DirEntry] {
        match &self.info {
            NodeInfo::Dir { children } => children,
            _ => &[],
        }
    }

    /// Get mutable children of a directory node.
    pub fn children_mut(&mut self) -> &mut Vec<DirEntry> {
        match &mut self.info {
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
