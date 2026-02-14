pub const SYS_READ: i32 = 0;
pub const SYS_WRITE: i32 = 1;
pub const SYS_OPEN: i32 = 2;
pub const SYS_CLOSE: i32 = 3;
pub const SYS_XSTAT: i32 = 4;
pub const SYS_FXSTAT: i32 = 5;
pub const SYS_POLL: i32 = 7;
pub const SYS_LSEEK: i32 = 8;
pub const SYS_MMAP: i32 = 9;
pub const SYS_MPROTECT: i32 = 10;
pub const SYS_MUNMAP: i32 = 11;
pub const SYS_BRK: i32 = 12;
pub const SYS_SIGACTION: i32 = 13;
pub const SYS_SIGPROCMASK: i32 = 14;

pub const SYS_IOCTL: i32 = 16;
pub const SYS_PREAD: i32 = 17;
pub const SYS_PWRITE: i32 = 18;
pub const SYS_WRITEV: i32 = 20;
pub const SYS_ACCESS: i32 = 21;
pub const SYS_PIPE: i32 = 22;
pub const SYS_SELECT: i32 = 23;
pub const SYS_SCHED_YIELD: i32 = 24;

pub const SYS_SHMGET: i32 = 29;
pub const SYS_SHMAT: i32 = 30;
pub const SYS_SHMCTL: i32 = 31;

pub const SYS_DUP: i32 = 32;
pub const SYS_DUP2: i32 = 33;

pub const SYS_NANOSLEEP_TIME64: i32 = 35;
pub const SYS_SETITIMER: i32 = 38;

pub const SYS_GETPID: i32 = 39;

pub const SYS_SOCKET: i32 = 41;
pub const SYS_CONNECT: i32 = 42;
pub const SYS_ACCEPT: i32 = 43;
pub const SYS_SENDTO: i32 = 44;
pub const SYS_RECVFROM: i32 = 45;
pub const SYS_SENDMSG: i32 = 46;
pub const SYS_RECVMSG: i32 = 47;
pub const SYS_SHUTDOWN: i32 = 48;
pub const SYS_BIND: i32 = 49;
pub const SYS_LISTEN: i32 = 50;
pub const SYS_GETSOCKNAME: i32 = 51;
pub const SYS_GETPEERNAME: i32 = 52;
pub const SYS_SOCKETPAIR: i32 = 53;
pub const SYS_SETSOCKOPT: i32 = 54;
pub const SYS_GETSOCKOPT: i32 = 55;

pub const SYS_CLONE: i32 = 56;
pub const SYS_FORK: i32 = 57;
pub const SYS_EXEC: i32 = 59;
pub const SYS_EXECVE: i32 = 59;
pub const SYS_EXIT: i32 = 60;
pub const SYS_WAITPID: i32 = 61;
pub const SYS_KILL: i32 = 62;

pub const SYS_SHMDT: i32 = 67;

pub const SYS_FCNTL: i32 = 72;
pub const SYS_FLOCK: i32 = 73;
pub const SYS_FSYNC: i32 = 74;
pub const SYS_FDATASYNC: i32 = 75;
pub const SYS_TRUNCATE: i32 = 76;
pub const SYS_FTRUNCATE: i32 = 77;
pub const SYS_GETDENTS: i32 = 78;
pub const SYS_GETCWD: i32 = 79;
pub const SYS_CHDIR: i32 = 80;
pub const SYS_FCHDIR: i32 = 81;
pub const SYS_RENAME: i32 = 82;
pub const SYS_UNLINK: i32 = 87;
pub const SYS_READLINK: i32 = 89;

pub const SYS_CHMOD: i32 = 90;
pub const SYS_FCHMOD: i32 = 91;
pub const SYS_GETUID: i32 = 102;
pub const SYS_GETGID: i32 = 104;
pub const SYS_GETEUID: i32 = 107;
pub const SYS_GETEGID: i32 = 108;
pub const SYS_GETPPID: i32 = 110;

pub const SYS_STATFS: i32 = 137;
pub const SYS_FSTATFS: i32 = 138;

pub const SYS_GETHOSTNAME: i32 = 170;
pub const SYS_FUTEX: i32 = 202;
pub const SYS_EPOLL_CREATE: i32 = 213;

pub const SYS_CLOCK_GETTIME: i32 = 228;
pub const SYS_EPOLL_WAIT: i32 = 232;
pub const SYS_EPOLL_CTL: i32 = 233;
pub const SYS_UNLINKAT: i32 = 263;
pub const SYS_READLINKAT: i32 = 267;
pub const SYS_SYNC_FILE_RANGE: i32 = 277;

pub const SYS_EPOLL_CREATE1: i32 = 291;
pub const SYS_DUP3: i32 = 292;
pub const SYS_PIPE2: i32 = 293;

pub const SYS_GETRANDOM: i32 = 318;
