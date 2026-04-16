use grate_rs::{
    constants::{
        SYS_ACCEPT, SYS_CLONE, SYS_CONNECT, SYS_DUP, SYS_DUP2, SYS_EXECVE, SYS_READ, SYS_WRITE,
        error::EIO,
    },
    copy_data_between_cages, getcageid, make_threei_call,
};

use rustls::{ClientConfig, ClientConnection, ServerConfig, ServerConnection, StreamOwned};
use std::{
    collections::HashMap,
    io::{Read, Write},
    sync::{Arc, Mutex, OnceLock},
};

// Global Contexts for Rustls
pub static SERVER_CONFIG: OnceLock<Arc<ServerConfig>> = OnceLock::new();
pub static CLIENT_CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
pub static NEXT_SESSION_ID: Mutex<u64> = Mutex::new(1);

// socket adapter
pub struct ThreeiSocket {
    pub real_fd: u64,
    pub fd_owner_cage: u64,
}

// store both client and aerver streams
pub enum TlsStream {
    Server(StreamOwned<ServerConnection, ThreeiSocket>),
    Client(StreamOwned<ClientConnection, ThreeiSocket>),
}

pub static TLS_SESSIONS: Mutex<Option<HashMap<u64, TlsStream>>> = Mutex::new(None);

impl Read for ThreeiSocket {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let this_cage = getcageid();

        println!("[ThreeiSocket]: This cageid: {:#?}", this_cage);

        let ret = make_threei_call(
            SYS_READ as u32,
            0,
            this_cage,
            self.fd_owner_cage,
            self.real_fd,
            self.fd_owner_cage,
            buf.as_mut_ptr() as u64,
            this_cage | (1u64 << 63),
            buf.len() as u64,
            this_cage,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        );
        match ret {
            Ok(bytes) if bytes >= 0 => Ok(bytes as usize),
            Ok(err_code) => {
                eprintln!(
                    "[mtls-grate] ThreeiSocket::read returned POSIX error: {}",
                    err_code
                );
                Err(std::io::Error::from_raw_os_error(libc::EIO))
            }
            Err(e) => {
                eprintln!(
                    "[mtls-grate] ThreeiSocket::read make_threei_call failed: {:?}",
                    e
                );
                Err(std::io::Error::from_raw_os_error(EIO))
            }
        }
    }
}

impl Write for ThreeiSocket {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let this_cage = getcageid();

        let ret = make_threei_call(
            SYS_WRITE as u32,
            0,
            this_cage,
            self.fd_owner_cage,
            self.real_fd,
            self.fd_owner_cage,
            buf.as_ptr() as u64,
            this_cage | (1u64 << 63),
            buf.len() as u64,
            this_cage,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        );
        match ret {
            Ok(bytes) if bytes >= 0 => Ok(bytes as usize),
            Ok(err_code) => {
                eprintln!(
                    "[mtls-grate] ThreeiSocket::write returned POSIX error: {}",
                    err_code
                );
                Err(std::io::Error::from_raw_os_error(libc::EIO))
            }
            Err(e) => {
                eprintln!(
                    "[mtls-grate] ThreeiSocket::write make_threei_call failed: {:?}",
                    e
                );
                Err(std::io::Error::from_raw_os_error(EIO))
            }
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// HANDLERS

pub extern "C" fn connect_syscall(
    cageid: u64,
    fd: u64,
    fd_cage: u64,
    addr: u64,
    addr_cage: u64,
    len: u64,
    len_cage: u64,
    arg4: u64,
    arg4cage: u64,
    arg5: u64,
    arg5cage: u64,
    arg6: u64,
    arg6cage: u64,
) -> i32 {
    let this_cage = getcageid();

    let real_fd = fd;

    // forward connect() call to the server
    let ret = match make_threei_call(
        SYS_CONNECT as u32,
        0,
        this_cage,
        fd_cage,
        real_fd,
        fd_cage,
        addr,
        addr_cage,
        len,
        len_cage,
        arg4,
        arg4cage,
        arg5,
        arg5cage,
        arg6,
        arg6cage,
        0,
    ) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[mtls-grate] SYS_CONNECT: make_threei_call failed: {:?}", e);
            return -1;
        }
    };

    if ret < 0 {
        return ret;
    }

    // initialize the rustls client connection
    let config = CLIENT_CONFIG
        .get()
        .expect("Client config not loaded")
        .clone();

    // TODO: parse the addr buffer to extract the real hostname
    let server_name = "localhost".try_into().unwrap();
    let conn = match ClientConnection::new(config, server_name) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "[mtls-grate] SYS_CONNECT: Failed to create TLS connection: {:?}",
                e
            );
            return -1;
        }
    };

    // wrap and store the stream
    let socket = ThreeiSocket {
        real_fd: real_fd,
        fd_owner_cage: fd_cage,
    };
    let stream = StreamOwned::new(conn, socket);

    let session_id = {
        let mut id_guard = NEXT_SESSION_ID.lock().unwrap();
        let current_id = *id_guard;
        *id_guard += 1;
        current_id
    };
    TLS_SESSIONS
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .insert(session_id, TlsStream::Client(stream));

    // attach the session_id to the existing virtual FD
    if let Err(e) = fdtables::set_perfdinfo(cageid, fd, session_id) {
        eprintln!("[mtls-grate] SYS_CONNECT: set_perfdinfo failed: {:?}", e);
        return -1;
    }

    ret
}

pub extern "C" fn accept_syscall(
    cageid: u64,
    fd: u64,
    fd_cage: u64,
    addr: u64,
    addr_cage: u64,
    len: u64,
    len_cage: u64,
    arg4: u64,
    arg4cage: u64,
    arg5: u64,
    arg5cage: u64,
    arg6: u64,
    arg6cage: u64,
) -> i32 {
    let this_cage = getcageid();
    println!("[Accept call]: this cage: {:#?}", this_cage);
    let real_listen_fd = fd;

    let real_new_fd = match make_threei_call(
        SYS_ACCEPT as u32,
        0,
        this_cage,
        fd_cage,
        real_listen_fd,
        fd_cage,
        addr,
        addr_cage,
        len,
        len_cage,
        arg4,
        arg4cage,
        arg5,
        arg5cage,
        arg6,
        arg6cage,
        0,
    ) {
        Ok(r) if r >= 0 => r as u64,
        Ok(r) => {
            eprintln!("[mtls-grate] SYS_ACCEPT: underlying accept returned {}", r);
            return -1;
        }
        Err(e) => {
            eprintln!("[mtls-grate] SYS_ACCEPT: make_threei_call failed: {:?}", e);
            return -1;
        }
    };

    let config = SERVER_CONFIG
        .get()
        .expect("Server config not loaded")
        .clone();
    let conn = match ServerConnection::new(config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "[mtls-grate] SYS_ACCEPT: Failed to create TLS connection: {:?}",
                e
            );
            return -1;
        }
    };

    let socket = ThreeiSocket {
        real_fd: real_new_fd,
        fd_owner_cage: fd_cage,
    };

    let stream = StreamOwned::new(conn, socket);

    let session_id = {
        let mut id_guard = NEXT_SESSION_ID.lock().unwrap();
        let current_id = *id_guard;
        *id_guard += 1;
        current_id
    };
    TLS_SESSIONS
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .insert(session_id, TlsStream::Server(stream));

    // map the read FD to virtual FD and attach session_id
    let real_new_fd = match fdtables::get_unused_virtual_fd(cageid, 0, real_new_fd, false, 0) {
        Ok(vfd) => vfd,
        Err(e) => {
            eprintln!(
                "[mtls-grate] SYS_ACCEPT: get_unused_virtual_fd failed: {:?}",
                e
            );
            return -1;
        }
    };

    if let Err(e) = fdtables::set_perfdinfo(cageid, real_new_fd, session_id) {
        eprintln!("[mtls-grate] SYS_ACCEPT: set_perfdinfo failed: {:?}", e);
        return -1;
    }

    real_new_fd as i32
}

pub extern "C" fn read_syscall(
    cageid: u64,
    fd: u64,
    fd_cage: u64,
    buf: u64,
    buf_cage: u64,
    count: u64,
    count_cage: u64,
    arg4: u64,
    arg4cage: u64,
    arg5: u64,
    arg5cage: u64,
    arg6: u64,
    arg6cage: u64,
) -> i32 {
    let this_cage = getcageid();

    // translate the virtual fd to retrieve the session info
    let fd_entry = match fdtables::translate_virtual_fd(cageid, fd) {
        Ok(entry) => entry,
        Err(_) => return -1,
    };

    let session_id = fd_entry.perfdinfo;

    // forward the call natively if there is no session ID
    if session_id == 0 {
        return match make_threei_call(
            SYS_READ as u32,
            0,
            this_cage,
            fd_cage,
            fd_entry.underfd,
            fd_cage,
            buf,
            buf_cage,
            count,
            count_cage,
            arg4,
            arg4cage,
            arg5,
            arg5cage,
            arg6,
            arg6cage,
            0,
        ) {
            Ok(r) => r,
            Err(e) => {
                eprintln!(
                    "[mtls-grate] SYS_READ (plaintext): make_threei_call failed: {:?}",
                    e
                );
                -1
            }
        };
    }

    // buffer to store decrypted results
    let mut plaintext = vec![0u8; count as usize];

    // read from the encrypted stream
    let bytes_read = {
        let mut guard = TLS_SESSIONS.lock().unwrap();
        let sessions = guard.as_mut().unwrap();

        if let Some(stream_enum) = sessions.get_mut(&session_id) {
            match stream_enum {
                TlsStream::Server(stream) => match stream.read(&mut plaintext) {
                    Ok(b) => b,
                    Err(e) => {
                        eprintln!("[mtls-grate] SYS_READ: Server stream read failed: {:?}", e);
                        return -1;
                    }
                },
                TlsStream::Client(stream) => match stream.read(&mut plaintext) {
                    Ok(b) => b,
                    Err(e) => {
                        eprintln!("[mtls-grate] SYS_READ: Client stream read failed: {:?}", e);
                        return -1;
                    }
                },
            }
        } else {
            eprintln!(
                "[mtls-grate] SYS_READ: Session ID {} not found in map!",
                session_id
            );
            return -1;
        }
    };

    // copy decrypted plaintext
    if let Err(e) = copy_data_between_cages(
        this_cage,
        this_cage,
        plaintext.as_ptr() as u64,
        this_cage,
        buf,
        buf_cage,
        bytes_read as u64,
        1,
    ) {
        eprintln!(
            "[mtls-grate] SYS_READ: copy_data_between_cages failed: {:?}",
            e
        );
        return -1;
    }

    bytes_read as i32
}

pub extern "C" fn write_syscall(
    cageid: u64,
    fd: u64,
    fd_cage: u64,
    buf: u64,
    buf_cage: u64,
    count: u64,
    count_cage: u64,
    arg4: u64,
    arg4cage: u64,
    arg5: u64,
    arg5cage: u64,
    arg6: u64,
    arg6cage: u64,
) -> i32 {
    let this_cage = getcageid();

    // translate the virtual fd
    let fd_entry = match fdtables::translate_virtual_fd(cageid, fd) {
        Ok(entry) => entry,
        Err(_) => return -1,
    };

    let session_id = fd_entry.perfdinfo;

    // forward the call natively if there is no session ID
    if session_id == 0 {
        return match make_threei_call(
            SYS_WRITE as u32,
            0,
            this_cage,
            fd_cage,
            fd_entry.underfd,
            fd_cage,
            buf,
            buf_cage,
            count,
            count_cage,
            arg4,
            arg4cage,
            arg5,
            arg5cage,
            arg6,
            arg6cage,
            0,
        ) {
            Ok(r) => r,
            Err(e) => {
                eprintln!(
                    "[mtls-grate] SYS_WRITE (plaintext): make_threei_call failed: {:?}",
                    e
                );
                -1
            }
        };
    }

    // copy plaintext from cage into the grate's memory
    let mut plaintext = vec![0u8; count as usize];

    if let Err(e) = copy_data_between_cages(
        this_cage,
        buf_cage,
        buf,
        buf_cage,
        plaintext.as_mut_ptr() as u64,
        this_cage,
        count,
        1,
    ) {
        eprintln!(
            "[mtls-grate] SYS_WRITE: copy_data_between_cages failed: {:?}",
            e
        );
        return -1;
    }

    // write to the encrypted stream
    let bytes_written = {
        let mut guard = TLS_SESSIONS.lock().unwrap();
        let session = guard.as_mut().unwrap();

        if let Some(stream_enum) = session.get_mut(&session_id) {
            match stream_enum {
                TlsStream::Server(stream) => match stream.write(&mut plaintext) {
                    Ok(b) => b,
                    Err(e) => {
                        eprintln!(
                            "[mtls-grate] SYS_WRITE: Server stream write failed: {:?}",
                            e
                        );
                        return -1;
                    }
                },
                TlsStream::Client(stream) => match stream.write(&mut plaintext) {
                    Ok(b) => b,
                    Err(e) => {
                        eprintln!(
                            "[mtls-grate] SYS_WRITE: Client stream write failed: {:?}",
                            e
                        );
                        return -1;
                    }
                },
            }
        } else {
            eprintln!(
                "[mtls-grate] SYS_WRITE: Session ID {} not found in map!",
                session_id
            );
            return -1;
        }
    };

    bytes_written as i32
}

pub extern "C" fn fork_syscall(
    _cageid: u64,
    arg1: u64,
    arg1cage: u64,
    arg2: u64,
    arg2cage: u64,
    arg3: u64,
    arg3cage: u64,
    arg4: u64,
    arg4cage: u64,
    arg5: u64,
    arg5cage: u64,
    arg6: u64,
    arg6cage: u64,
) -> i32 {
    let this_cage = getcageid();
    let cage_id = arg1cage;

    let ret = match make_threei_call(
        SYS_CLONE as u32,
        0,
        this_cage,
        cage_id,
        arg1,
        arg1cage,
        arg2,
        arg2cage,
        arg3,
        arg3cage,
        arg4,
        arg4cage,
        arg5,
        arg5cage,
        arg6,
        arg6cage,
        0,
    ) {
        Ok(ret) => ret,
        Err(_) => -1,
    };

    if ret <= 0 {
        return ret;
    }

    let child_cageid = ret as u64;
    let _ = fdtables::copy_fdtable_for_cage(cage_id, child_cageid as u64);

    child_cageid as i32
}

pub extern "C" fn exec_syscall(
    _cageid: u64,
    arg1: u64,
    arg1cage: u64,
    arg2: u64,
    arg2cage: u64,
    arg3: u64,
    arg3cage: u64,
    arg4: u64,
    arg4cage: u64,
    arg5: u64,
    arg5cage: u64,
    arg6: u64,
    arg6cage: u64,
) -> i32 {
    let this_cage = getcageid();
    let cage_id = arg1cage;

    fdtables::empty_fds_for_exec(cage_id);

    for fd in 0..3u64 {
        let _ = fdtables::get_specific_virtual_fd(cage_id, fd, 0, fd, false, 0);
    }

    match make_threei_call(
        SYS_EXECVE as u32,
        0,
        this_cage,
        cage_id,
        arg1,
        arg1cage,
        arg2,
        arg2cage,
        arg3,
        arg3cage,
        arg4,
        arg4cage,
        arg5,
        arg5cage,
        arg6,
        arg6cage,
        0,
    ) {
        Ok(ret) => ret,
        Err(_) => -1,
    }
}

pub extern "C" fn dup_syscall(
    _cageid: u64,
    arg1: u64,
    arg1cage: u64,
    arg2: u64,
    arg2cage: u64,
    arg3: u64,
    arg3cage: u64,
    arg4: u64,
    arg4cage: u64,
    arg5: u64,
    arg5cage: u64,
    arg6: u64,
    arg6cage: u64,
) -> i32 {
    let this_cage = getcageid();
    let cage_id = arg1cage;
    let fd = arg1;

    let ret = match make_threei_call(
        SYS_DUP as u32,
        0,
        this_cage,
        cage_id,
        arg1,
        arg1cage,
        arg2,
        arg2cage,
        arg3,
        arg3cage,
        arg4,
        arg4cage,
        arg5,
        arg5cage,
        arg6,
        arg6cage,
        0,
    ) {
        Ok(ret) => ret,
        Err(_) => -1,
    };

    if ret >= 0 {
        if let Ok(entry) = fdtables::translate_virtual_fd(cage_id, fd) {
            let _ = fdtables::get_specific_virtual_fd(
                cage_id,
                ret as u64,
                entry.fdkind,
                entry.underfd,
                entry.should_cloexec,
                entry.perfdinfo,
            );
        }
    }

    ret
}

pub extern "C" fn dup2_syscall(
    _cageid: u64,
    arg1: u64,
    arg1cage: u64,
    arg2: u64,
    arg2cage: u64,
    arg3: u64,
    arg3cage: u64,
    arg4: u64,
    arg4cage: u64,
    arg5: u64,
    arg5cage: u64,
    arg6: u64,
    arg6cage: u64,
) -> i32 {
    let this_cage = getcageid();
    let cage_id = arg1cage;
    let oldfd = arg1;
    let newfd = arg2;

    let ret = match make_threei_call(
        SYS_DUP2 as u32,
        0,
        this_cage,
        cage_id,
        arg1,
        arg1cage,
        arg2,
        arg2cage,
        arg3,
        arg3cage,
        arg4,
        arg4cage,
        arg5,
        arg5cage,
        arg6,
        arg6cage,
        0,
    ) {
        Ok(ret) => ret,
        Err(_) => -1,
    };

    if ret >= 0 {
        if let Ok(entry) = fdtables::translate_virtual_fd(cage_id, oldfd) {
            let _ = fdtables::get_specific_virtual_fd(
                cage_id,
                newfd,
                entry.fdkind,
                entry.underfd,
                entry.should_cloexec,
                entry.perfdinfo,
            );
        }
    }
    ret
}
