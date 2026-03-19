#ifndef STRACE_H
#define STRACE_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <lind_syscall.h>

#define MAX_SYSCALLS 334

#define WL 0   // Whitelist
#define BL 1   // Blacklist

// function ptr for storing syscall handlers
typedef int (*syscall_handler_t)(
    uint64_t cageid,
    uint64_t arg1, uint64_t arg1cage,
    uint64_t arg2, uint64_t arg2cage,
    uint64_t arg3, uint64_t arg3cage,
    uint64_t arg4, uint64_t arg4cage,
    uint64_t arg5, uint64_t arg5cage,
    uint64_t arg6, uint64_t arg6cage
);

// syscall handler table
extern syscall_handler_t syscall_handler_table[MAX_SYSCALLS];

// lookup mapping handler
typedef struct{
    const char *name;
    int num;
    syscall_handler_t handler;
} syscall_entry_t;

// array to track list type
extern int syscall_mode[MAX_SYSCALLS];

// generic handler macro
#define DEFINE_HANDLER(name, num)                                             \
int name##_grate(                                                             \
    uint64_t cageid,                                                          \
    uint64_t arg1, uint64_t arg1cage, uint64_t arg2, uint64_t arg2cage,       \
    uint64_t arg3, uint64_t arg3cage, uint64_t arg4, uint64_t arg4cage,       \
    uint64_t arg5, uint64_t arg5cage, uint64_t arg6, uint64_t arg6cage)       \
{                                                                             \
    /* Check the runtime configuration for this specific syscall */           \
    if (syscall_mode[num] == BL) {                                            \
        return -EPERM;                                                        \
    }                                                                         \
                                                                              \
    int thiscage = getpid();                                                  \
    return make_threei_call(                                                  \
        num, 0,                                                               \
        thiscage, arg1cage,                                                   \
        arg1, arg1cage, arg2, arg2cage,                                       \
        arg3, arg3cage, arg4, arg4cage,                                       \
        arg5, arg5cage, arg6, arg6cage, 0);                                   \
}

// function to parse INI config file
void parse_config(const char *filename);

#endif
