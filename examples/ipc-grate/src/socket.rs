//! Socket state machine and connection infrastructure.
//!
//! Unix domain sockets (AF_UNIX) and loopback sockets (AF_INET 127.0.0.1)
//! are both backed by EmulatedPipe pairs in the ipc-grate, eliminating
//! kernel round-trips for inter-cage IPC.
//!
//! Modeled on safeposix-rust's SocketHandle and UnixSocketInfo:
//!   - Each connected socket has a sendpipe and receivepipe
//!   - socketpair creates two sockets with swapped pipe directions
//!   - connect/accept handshake creates pipe pairs and swaps them
//!   - send → write to sendpipe, recv → read from receivepipe
//!
//! # Buffer sizes
//!   - AF_UNIX pipes: 212,992 bytes (matching safeposix UDSOCK_CAPACITY)
//!   - AF_INET loopback pipes: same size

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::pipe::PipeBuffer;

/// Buffer capacity for unix domain socket pipes (matches safeposix).
pub const UDSOCK_CAPACITY: usize = 212_992;

// Socket domains.
pub const AF_UNIX: i32 = 1;
pub const AF_INET: i32 = 2;

// Socket types.
pub const SOCK_STREAM: i32 = 1;
pub const SOCK_DGRAM: i32 = 2;

// Shutdown modes.
pub const SHUT_RD: i32 = 0;
pub const SHUT_WR: i32 = 1;
pub const SHUT_RDWR: i32 = 2;

/// fdtables fdkind for socket descriptors.
pub const IPC_SOCKET: u32 = 3;

/// Connection state of a socket.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ConnState {
    /// Not connected to anything.
    NotConnected,
    /// Fully connected (bidirectional).
    Connected,
    /// Write direction shut down (can only read).
    ReadOnly,
    /// Read direction shut down (can only write).
    WriteOnly,
    /// Listening for incoming connections.
    Listening,
}

/// Per-socket state. Stored in the IpcState socket registry,
/// keyed by a unique socket_id (stored as underfd in fdtables).
#[derive(Clone)]
pub struct SocketInfo {
    pub domain: i32,
    pub socktype: i32,
    pub state: ConnState,
    pub flags: i32,

    /// Bound address (path for AF_UNIX, port for AF_INET loopback).
    pub local_addr: Option<String>,
    /// Remote address (set after connect/accept).
    pub remote_addr: Option<String>,

    /// Send direction pipe (we write to this to send to the peer).
    pub sendpipe: Option<Arc<PipeBuffer>>,
    /// Receive direction pipe (we read from this to receive from the peer).
    pub recvpipe: Option<Arc<PipeBuffer>>,
}

impl SocketInfo {
    pub fn new(domain: i32, socktype: i32, flags: i32) -> Self {
        SocketInfo {
            domain,
            socktype,
            state: ConnState::NotConnected,
            flags,
            local_addr: None,
            remote_addr: None,
            sendpipe: None,
            recvpipe: None,
        }
    }
}

/// A pending connection waiting in the accept queue.
/// Created by connect(), consumed by accept().
pub struct PendingConnection {
    /// The connecting socket's address.
    pub remote_addr: String,
    /// Pipe: connector writes here → listener reads from here.
    pub pipe_to_listener: Arc<PipeBuffer>,
    /// Pipe: listener writes here → connector reads from here.
    pub pipe_to_connector: Arc<PipeBuffer>,
}

/// Global socket state: socket registry + accept queue + bind paths.
pub struct SocketRegistry {
    /// socket_id → SocketInfo. The socket_id is stored as underfd in fdtables.
    pub sockets: HashMap<u64, SocketInfo>,
    /// Next socket_id to allocate.
    pub next_socket_id: u64,

    /// Pending connections keyed by the listening address.
    /// connect() pushes here, accept() pops from here.
    pub pending_connections: HashMap<String, Vec<PendingConnection>>,

    /// Set of bound unix socket paths (for checking if a path is valid to connect to).
    pub bound_paths: HashMap<String, u64>, // path → socket_id of the listener

    /// Loopback port allocation: port → socket_id of the listener.
    pub bound_ports: HashMap<u16, u64>,
    /// Next ephemeral port for loopback (counts down from 60999).
    pub next_ephemeral_port: u16,
}

impl SocketRegistry {
    pub fn new() -> Self {
        SocketRegistry {
            sockets: HashMap::new(),
            next_socket_id: 0,
            pending_connections: HashMap::new(),
            bound_paths: HashMap::new(),
            bound_ports: HashMap::new(),
            next_ephemeral_port: 60999,
        }
    }

    /// Create a new socket and return its socket_id.
    pub fn create_socket(&mut self, domain: i32, socktype: i32, flags: i32) -> u64 {
        let id = self.next_socket_id;
        self.next_socket_id += 1;
        self.sockets.insert(id, SocketInfo::new(domain, socktype, flags));
        id
    }

    /// Get a socket by its id.
    pub fn get(&self, socket_id: u64) -> Option<&SocketInfo> {
        self.sockets.get(&socket_id)
    }

    /// Get a mutable socket by its id.
    pub fn get_mut(&mut self, socket_id: u64) -> Option<&mut SocketInfo> {
        self.sockets.get_mut(&socket_id)
    }

    /// Remove a socket from the registry.
    pub fn remove(&mut self, socket_id: u64) {
        if let Some(sock) = self.sockets.remove(&socket_id) {
            // Clean up bound paths/ports.
            if let Some(ref addr) = sock.local_addr {
                self.bound_paths.remove(addr);
            }
        }
    }

    /// Allocate an ephemeral loopback port. Returns the port number.
    pub fn alloc_ephemeral_port(&mut self) -> Option<u16> {
        let start = self.next_ephemeral_port;
        let mut port = start;
        loop {
            if !self.bound_ports.contains_key(&port) {
                self.next_ephemeral_port = if port > 32768 { port - 1 } else { 60999 };
                return Some(port);
            }
            port = if port > 32768 { port - 1 } else { 60999 };
            if port == start {
                return None; // All ports exhausted.
            }
        }
    }

    /// Create a connected socketpair. Returns (socket_id_1, socket_id_2).
    ///
    /// Creates two pipes with swapped directions:
    ///   socket1.sendpipe = pipe_a,  socket1.recvpipe = pipe_b
    ///   socket2.sendpipe = pipe_b,  socket2.recvpipe = pipe_a
    /// So socket1 writing to pipe_a is read by socket2 from pipe_a.
    pub fn create_socketpair(
        &mut self,
        domain: i32,
        socktype: i32,
        flags: i32,
    ) -> (u64, u64) {
        let pipe_a = Arc::new(PipeBuffer::new(UDSOCK_CAPACITY));
        let pipe_b = Arc::new(PipeBuffer::new(UDSOCK_CAPACITY));

        let id1 = self.create_socket(domain, socktype, flags);
        let id2 = self.create_socket(domain, socktype, flags);

        // Swap pipe directions between the two sockets.
        if let Some(s1) = self.sockets.get_mut(&id1) {
            s1.sendpipe = Some(pipe_a.clone());
            s1.recvpipe = Some(pipe_b.clone());
            s1.state = ConnState::Connected;
        }
        if let Some(s2) = self.sockets.get_mut(&id2) {
            s2.sendpipe = Some(pipe_b);
            s2.recvpipe = Some(pipe_a);
            s2.state = ConnState::Connected;
        }

        (id1, id2)
    }

    /// Establish a connection (called during accept).
    /// Creates pipe pair, assigns to both connector and acceptor sockets.
    pub fn establish_connection(
        &mut self,
        connector_id: u64,
        acceptor_id: u64,
    ) {
        let pipe_to_acceptor = Arc::new(PipeBuffer::new(UDSOCK_CAPACITY));
        let pipe_to_connector = Arc::new(PipeBuffer::new(UDSOCK_CAPACITY));

        if let Some(conn) = self.sockets.get_mut(&connector_id) {
            conn.sendpipe = Some(pipe_to_acceptor.clone());
            conn.recvpipe = Some(pipe_to_connector.clone());
            conn.state = ConnState::Connected;
        }
        if let Some(acc) = self.sockets.get_mut(&acceptor_id) {
            acc.sendpipe = Some(pipe_to_connector);
            acc.recvpipe = Some(pipe_to_acceptor);
            acc.state = ConnState::Connected;
        }
    }
}

// =====================================================================
//  Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_socket() {
        let mut reg = SocketRegistry::new();
        let id = reg.create_socket(AF_UNIX, SOCK_STREAM, 0);
        let sock = reg.get(id).unwrap();
        assert_eq!(sock.domain, AF_UNIX);
        assert_eq!(sock.state, ConnState::NotConnected);
    }

    #[test]
    fn test_socketpair_creates_connected_pair() {
        let mut reg = SocketRegistry::new();
        let (id1, id2) = reg.create_socketpair(AF_UNIX, SOCK_STREAM, 0);

        let s1 = reg.get(id1).unwrap();
        let s2 = reg.get(id2).unwrap();

        assert_eq!(s1.state, ConnState::Connected);
        assert_eq!(s2.state, ConnState::Connected);
        assert!(s1.sendpipe.is_some());
        assert!(s1.recvpipe.is_some());
    }

    #[test]
    fn test_socketpair_pipes_are_swapped() {
        let mut reg = SocketRegistry::new();
        let (id1, id2) = reg.create_socketpair(AF_UNIX, SOCK_STREAM, 0);

        let s1 = reg.get(id1).unwrap();
        let s2 = reg.get(id2).unwrap();

        // Write through socket1's sendpipe.
        s1.sendpipe.as_ref().unwrap().write(b"from s1", 7, false);

        // Read from socket2's recvpipe — should get the same data.
        let mut buf = [0u8; 16];
        let nr = s2.recvpipe.as_ref().unwrap().read(&mut buf, 16, false);
        assert_eq!(nr, 7);
        assert_eq!(&buf[..7], b"from s1");
    }

    #[test]
    fn test_socketpair_bidirectional() {
        let mut reg = SocketRegistry::new();
        let (id1, id2) = reg.create_socketpair(AF_UNIX, SOCK_STREAM, 0);

        let s1 = reg.get(id1).unwrap();
        let s2 = reg.get(id2).unwrap();

        // s1 → s2
        s1.sendpipe.as_ref().unwrap().write(b"hello", 5, false);
        let mut buf = [0u8; 16];
        let nr = s2.recvpipe.as_ref().unwrap().read(&mut buf, 16, false);
        assert_eq!(&buf[..nr as usize], b"hello");

        // s2 → s1
        s2.sendpipe.as_ref().unwrap().write(b"world", 5, false);
        let nr = s1.recvpipe.as_ref().unwrap().read(&mut buf, 16, false);
        assert_eq!(&buf[..nr as usize], b"world");
    }

    #[test]
    fn test_ephemeral_port_allocation() {
        let mut reg = SocketRegistry::new();
        let p1 = reg.alloc_ephemeral_port().unwrap();
        let p2 = reg.alloc_ephemeral_port().unwrap();
        assert_ne!(p1, p2);
        assert!(p1 >= 32768 && p1 <= 60999);
    }

    #[test]
    fn test_remove_socket_cleans_bound_path() {
        let mut reg = SocketRegistry::new();
        let id = reg.create_socket(AF_UNIX, SOCK_STREAM, 0);
        if let Some(s) = reg.get_mut(id) {
            s.local_addr = Some("/tmp/test.sock".to_string());
        }
        reg.bound_paths.insert("/tmp/test.sock".to_string(), id);

        reg.remove(id);
        assert!(!reg.bound_paths.contains_key("/tmp/test.sock"));
        assert!(reg.get(id).is_none());
    }
}
