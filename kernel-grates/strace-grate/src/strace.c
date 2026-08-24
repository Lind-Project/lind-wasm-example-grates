#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include "strace.h"

// table for storing syscall handlers
syscall_handler_t syscall_handler_table[MAX_SYSCALLS] = {0};

/* ---- path-taking value syscalls (ARG_STR marshaled by the macro) ---- */
DEFINE_HANDLER(chmod, __NR_chmod, ARG_STR, ARG_INT)
DEFINE_HANDLER(mkdir, __NR_mkdir, ARG_STR, ARG_INT)
DEFINE_HANDLER(rmdir, __NR_rmdir, ARG_STR)
DEFINE_HANDLER(chdir, __NR_chdir, ARG_STR)
DEFINE_HANDLER(truncate, __NR_truncate, ARG_STR, ARG_INT)
DEFINE_HANDLER(rename, __NR_rename, ARG_STR, ARG_STR)
DEFINE_HANDLER(link, __NR_link, ARG_STR, ARG_STR)
DEFINE_HANDLER(unlinkat, __NR_unlinkat, ARG_INT, ARG_STR, ARG_INT)

DEFINE_HANDLER(openat, __NR_openat, ARG_INT, ARG_STR, ARG_INT, ARG_INT)
DEFINE_HANDLER(read, __NR_read, ARG_INT, ARG_PTR, ARG_INT)
DEFINE_HANDLER(write, __NR_write, ARG_INT, ARG_PTR, ARG_INT)
DEFINE_HANDLER(pread64, __NR_pread64, ARG_INT, ARG_PTR, ARG_INT, ARG_INT)
DEFINE_HANDLER(pwrite64, __NR_pwrite64, ARG_INT, ARG_PTR, ARG_INT, ARG_INT)
DEFINE_HANDLER(fstat, __NR_fstat, ARG_INT, ARG_PTR)
DEFINE_HANDLER(readv, __NR_readv, ARG_INT, ARG_PTR, ARG_INT)
DEFINE_HANDLER(writev, __NR_writev, ARG_INT, ARG_PTR, ARG_INT)
DEFINE_HANDLER(close, __NR_close, ARG_INT)
DEFINE_HANDLER(lseek, __NR_lseek, ARG_INT, ARG_INT, ARG_INT)
DEFINE_HANDLER(dup, __NR_dup, ARG_INT)
DEFINE_HANDLER(dup2, __NR_dup2, ARG_INT, ARG_INT)
DEFINE_HANDLER(ftruncate, __NR_ftruncate, ARG_INT, ARG_INT)
DEFINE_HANDLER(fsync, __NR_fsync, ARG_INT)
DEFINE_HANDLER(unlink, __NR_unlink, ARG_STR)
DEFINE_HANDLER(access, __NR_access, ARG_STR, ARG_INT)

DEFINE_HANDLER(mmap, __NR_mmap, ARG_PTR, ARG_INT, ARG_INT, ARG_INT, ARG_INT, ARG_INT)
DEFINE_HANDLER(mprotect, __NR_mprotect, ARG_PTR, ARG_INT, ARG_INT)
DEFINE_HANDLER(munmap, __NR_munmap, ARG_PTR, ARG_INT)

DEFINE_HANDLER(getuid, __NR_getuid)
DEFINE_HANDLER(geteuid, __NR_geteuid)
DEFINE_HANDLER(getgid, __NR_getgid)
DEFINE_HANDLER(getegid, __NR_getegid)
DEFINE_HANDLER(sched_yield, __NR_sched_yield)
