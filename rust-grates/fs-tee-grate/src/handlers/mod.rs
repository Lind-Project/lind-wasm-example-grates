pub mod lifecycle;
pub mod tee;

pub use lifecycle::*;
// pub use tee::*;

use grate_rs::constants::*;

pub const FS_CALLS: [u64; 37] = [
    SYS_GETDENTS,
    258,
    SYS_OPEN,
    SYS_XSTAT,
    SYS_ACCESS,
    SYS_UNLINK,
    SYS_MMAP,
    SYS_MKDIR,
    SYS_RMDIR,
    SYS_RENAME,
    SYS_TRUNCATE,
    SYS_CHMOD,
    SYS_CHDIR,
    SYS_READLINK,
    SYS_UNLINKAT,
    SYS_READLINKAT,
    SYS_READ,
    SYS_WRITE,
    SYS_CLOSE,
    SYS_PREAD,
    SYS_PREADV,
    SYS_PWRITE,
    SYS_PWRITEV,
    SYS_FSYNC,
    SYS_LSEEK,
    SYS_FXSTAT,
    SYS_FCNTL,
    SYS_FTRUNCATE,
    SYS_FCHMOD,
    SYS_READV,
    SYS_WRITEV,
    SYS_DUP,
    SYS_DUP2,
    SYS_DUP3,
    SYS_PIPE,
    SYS_PIPE2,
    SYS_CLONE,
];
