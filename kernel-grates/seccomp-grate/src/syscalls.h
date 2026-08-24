#ifndef SYSCALLS_H
#define SYSCALLS_H

#include <sys/syscall.h>

/*
 * Map config syscall names to the KERNEL's __NR_* numbers (was lind numbering).
 * These are what register_handler expects and what syscall_mode[] is indexed
 * by. Guarded with #ifdef so names absent on this arch are simply skipped.
 * (e.g. lind's "nanosleep_time64" is a 32-bit name; on x86-64 use nanosleep.)
 */
#define X_IF(name, nr) X(name, nr)

#define SYSCALL_LIST \
  X(read,        __NR_read) \
  X(write,       __NR_write) \
  X(open,        __NR_open) \
  X(close,       __NR_close) \
  X(stat,        __NR_stat) \
  X(fstat,       __NR_fstat) \
  X(poll,        __NR_poll) \
  X(lseek,       __NR_lseek) \
  X(mmap,        __NR_mmap) \
  X(mprotect,    __NR_mprotect) \
  X(munmap,      __NR_munmap) \
  X(brk,         __NR_brk) \
  X(ioctl,       __NR_ioctl) \
  X(pread,       __NR_pread64) \
  X(pwrite,      __NR_pwrite64) \
  X(readv,       __NR_readv) \
  X(writev,      __NR_writev) \
  X(pipe,        __NR_pipe) \
  X(select,      __NR_select) \
  X(sched_yield, __NR_sched_yield) \
  X(dup,         __NR_dup) \
  X(dup2,        __NR_dup2) \
  X(nanosleep,   __NR_nanosleep) \
  X(setitimer,   __NR_setitimer) \
  X(getpid,      __NR_getpid) \
  X(socket,      __NR_socket) \
  X(connect,     __NR_connect) \
  X(accept,      __NR_accept) \
  X(sendto,      __NR_sendto) \
  X(recvfrom,    __NR_recvfrom) \
  X(sendmsg,     __NR_sendmsg) \
  X(recvmsg,     __NR_recvmsg) \
  X(shutdown,    __NR_shutdown) \
  X(bind,        __NR_bind) \
  X(listen,      __NR_listen) \
  X(getsockname, __NR_getsockname) \
  X(getpeername, __NR_getpeername) \
  X(socketpair,  __NR_socketpair) \
  X(setsockopt,  __NR_setsockopt) \
  X(getsockopt,  __NR_getsockopt) \
  X(fork,        __NR_fork) \
  X(exec,        __NR_execve) \
  X(exit,        __NR_exit) \
  X(kill,        __NR_kill) \
  X(fcntl,       __NR_fcntl) \
  X(flock,       __NR_flock) \
  X(fsync,       __NR_fsync) \
  X(fdatasync,   __NR_fdatasync) \
  X(truncate,    __NR_truncate) \
  X(ftruncate,   __NR_ftruncate) \
  X(getcwd,      __NR_getcwd) \
  X(chdir,       __NR_chdir) \
  X(fchdir,      __NR_fchdir) \
  X(rename,      __NR_rename) \
  X(mkdir,       __NR_mkdir) \
  X(rmdir,       __NR_rmdir) \
  X(link,        __NR_link) \
  X(unlink,      __NR_unlink) \
  X(readlink,    __NR_readlink) \
  X(chmod,       __NR_chmod) \
  X(fchmod,      __NR_fchmod) \
  X(getuid,      __NR_getuid) \
  X(getgid,      __NR_getgid) \
  X(geteuid,     __NR_geteuid) \
  X(getegid,     __NR_getegid) \
  X(getppid,     __NR_getppid) \
  X(mknod,       __NR_mknod) \
  X(statfs,      __NR_statfs) \
  X(fstatfs,     __NR_fstatfs) \
  X(futex,       __NR_futex) \
  X(clock_gettime, __NR_clock_gettime) \
  X(exit_group,  __NR_exit_group) \
  X(epoll_wait,  __NR_epoll_wait) \
  X(epoll_ctl,   __NR_epoll_ctl) \
  X(openat,      __NR_openat) \
  X(unlinkat,    __NR_unlinkat) \
  X(readlinkat,  __NR_readlinkat) \
  X(dup3,        __NR_dup3) \
  X(pipe2,       __NR_pipe2) \
  X(prlimit64,   __NR_prlimit64) \
  X(getrandom,   __NR_getrandom)

#endif
