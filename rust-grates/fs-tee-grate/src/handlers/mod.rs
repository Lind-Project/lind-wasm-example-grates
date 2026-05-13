pub mod lifecycle;
pub mod tee;

pub use lifecycle::*;

use grate_rs::{SyscallHandler, constants::*};

use crate::handlers::tee::*;

pub const FS_CALL_TABLE: &[(u64, SyscallHandler)] = &[
    (SYS_READ, tee_read),
    (SYS_WRITE, tee_write),
    (SYS_OPEN, tee_open),
    (SYS_CLOSE, tee_close),
    (SYS_XSTAT, tee_stat),
    (SYS_FXSTAT, tee_fstat),
    (SYS_LSEEK, tee_lseek),
    (SYS_MMAP, tee_mmap),
    (SYS_PREAD, tee_pread),
    (SYS_PWRITE, tee_pwrite),
    (SYS_READV, tee_readv),
    (SYS_WRITEV, tee_writev),
    (SYS_ACCESS, tee_access),
    (SYS_PIPE, tee_pipe),
    (SYS_DUP, tee_dup),
    (SYS_DUP2, tee_dup2),
    (SYS_CLONE, tee_fork),
    (SYS_FCNTL, tee_fcntl),
    (SYS_FSYNC, tee_fsync),
    (SYS_TRUNCATE, tee_truncate),
    (SYS_FTRUNCATE, tee_ftruncate),
    (SYS_GETDENTS, tee_getdents),
    (SYS_CHDIR, tee_chdir),
    (SYS_RENAME, tee_rename),
    (SYS_MKDIR, tee_mkdir),
    (SYS_RMDIR, tee_rmdir),
    (SYS_UNLINK, tee_unlink),
    (SYS_READLINK, tee_readlink),
    (SYS_CHMOD, tee_chmod),
    (SYS_FCHMOD, tee_fchmod),
    (SYS_MKDIRAT, tee_mkdirat),
    (SYS_UNLINKAT, tee_unlinkat),
    (SYS_READLINKAT, tee_readlinkat),
    (SYS_DUP3, tee_dup3),
    (SYS_PIPE2, tee_pipe2),
    (SYS_PREADV, tee_preadv),
    (SYS_PWRITEV, tee_pwritev),
];
