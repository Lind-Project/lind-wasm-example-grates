#ifndef STRACE_H
#define STRACE_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <lind_syscall.h>

#define ARG_INT 0
#define ARG_STR 1
#define ARG_PTR 2
#define MAX_SYSCALLS 334

#define WL 0   // Whitelist
#define BL 1   // Blacklist

// function ptr for storing syscall handlers
typedef int (*syscall_handler_t)(
    uint64_t, uint64_t, uint64_t, uint64_t,
    uint64_t, uint64_t, uint64_t, uint64_t,
    uint64_t, uint64_t, uint64_t, uint64_t,
    uint64_t
);

// table for storing syscall handlers
extern syscall_handler_t syscall_handler_table[MAX_SYSCALLS];


// whitelist handler
#define DEFINE_WL(name, num)                                                  \
int name##_grate(                                                             \
    uint64_t cageid,                                                          \
    uint64_t arg1, uint64_t arg1cage,                                         \
    uint64_t arg2, uint64_t arg2cage,                                         \
    uint64_t arg3, uint64_t arg3cage,                                         \
    uint64_t arg4, uint64_t arg4cage,                                         \
    uint64_t arg5, uint64_t arg5cage,                                         \
    uint64_t arg6, uint64_t arg6cage)                                         \
{                                                                             \
    int thiscage = getpid();                                                  \
                                                                              \
    /* forward whitelisted syscalls */                                        \
    int ret = make_threei_call(                                               \
        num, 0,                                                               \
        thiscage, arg1cage,                                                   \
        arg1, arg1cage, arg2, arg2cage,                                       \
        arg3, arg3cage, arg4, arg4cage,                                       \
        arg5, arg5cage, arg6, arg6cage, 0);                                   \
                                                                              \
	/* uncomment this out for tracing */                                  \
	/* fprintf(stderr, "[WL] %s = %d\n", #name, ret); */                  \
	                                                                      \
    return ret;                                                               \
}


// BLACKLIST HANDLER
#define DEFINE_BL(name, num)                                                  \
int name##_grate(                                                             \
    uint64_t cageid,                                                          \
    uint64_t arg1, uint64_t arg1cage,                                         \
    uint64_t arg2, uint64_t arg2cage,                                         \
    uint64_t arg3, uint64_t arg3cage,                                         \
    uint64_t arg4, uint64_t arg4cage,                                         \
    uint64_t arg5, uint64_t arg5cage,                                         \
    uint64_t arg6, uint64_t arg6cage)                                         \
{                                                                             \
                                                                              \
    /* uncomment this out for tracing */                                      \
    /* fprintf(stderr, "[BL] %s blocked\n", #name); */                        \
                                                                              \
    /* return operation not permitted for blacklisted syscalls */             \
    return -EPERM;                                                            \
}


// MAIN SELECTOR MACRO
#define DEFINE_FILTER(name, num, list, ...)                                   \
    DEFINE_##list(name, num)                                                  \
    __attribute__((constructor)) static void register_##name(void) {          \
        syscall_handler_table[num] = &name##_grate;                           \
    }

#endif
