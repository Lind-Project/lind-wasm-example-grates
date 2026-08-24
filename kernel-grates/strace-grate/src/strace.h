#ifndef STRACE_H
#define STRACE_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

#include <threei.h>        /* current 3i ABI (was <lind_syscall.h>) */

#define ARG_INT 0
#define ARG_STR 1
#define ARG_PTR 2
#define MAX_SYSCALLS 512      /* x86-64 needs > 334 (openat=257, statx=332) */

#define STRACE_STRBUF 4096    /* per-ARG_STR staging window in the grate */

/*
 * ABI CHANGE 1 — handler signature.
 * lind:  int  fn(cageid, arg1, arg1cage, ... arg6, arg6cage)   [14 scalars]
 * here:  long fn(pid_t cageid, const int arg_cage[6], unsigned long args[6])
 * `cageid` is the TARGET cage. The handler runs in the GRATE's context, so
 * getpid() inside it is the grate.
 */
typedef long (*syscall_handler_t)(pid_t cageid, const int arg_cage[6],
                                  unsigned long args[6]);

// table for storing syscall handlers
extern syscall_handler_t syscall_handler_table[MAX_SYSCALLS];

// macro for defining syscall handlers dynamically
#define DEFINE_HANDLER(name, num, ...)                                          \
    /* function defination for syscall handler */                               \
    long name##_grate(pid_t cageid, const int arg_cage[6],                      \
                      unsigned long args[6]) {                                  \
        int thiscage = getpid();                                                \
        int types[] = {__VA_ARGS__};                                            \
        int argsnum = sizeof(types) / sizeof(int);                              \
        unsigned long fwd[6];                                                   \
        char *strbuf[6] = {0};                                                  \
        long ret;                                                               \
                                                                                \
        char log_buffer[2048];                                                  \
        int offset = 0;                                                         \
                                                                                \
        for (int i = 0; i < 6; i++)                                             \
            fwd[i] = args[i];                                                   \
                                                                                \
        /* log buffer to print syscall with args and ret val */                 \
        offset += snprintf(log_buffer + offset, sizeof(log_buffer) - offset, "%s(", #name); \
                                                                                \
        for (int i = 0; i < argsnum; i++) {                                     \
            if (i > 0)                                                          \
                offset += snprintf(log_buffer + offset, sizeof(log_buffer) - offset, ", "); \
                                                                                \
            if (types[i] == ARG_STR && args[i] != 0) {                          \
                char *buf = malloc(STRACE_STRBUF);                              \
                if (buf) {                                                      \
                    /* arg_cage[i] == 0 means the primary (target) cage */      \
                    pid_t src = arg_cage[i] ? (pid_t)arg_cage[i] : cageid;      \
                    buf[0] = '\0';                                              \
                                                                                \
                    if (copy_data_between_cages(src, args[i],                   \
                                                (pid_t)thiscage,                \
                                                (unsigned long)buf,             \
                                                STRACE_STRBUF, 1) < 0) {        \
                        buf[0] = '\0';                                          \
                    }                                                           \
                    buf[STRACE_STRBUF - 1] = '\0';                              \
                                                                                \
                    strbuf[i] = buf;                                            \
                    fwd[i] = (unsigned long)buf;                                \
                    offset += snprintf(log_buffer + offset, sizeof(log_buffer) - offset, \
                                       "\"%s\"", buf);                          \
                } else {                                                        \
                    offset += snprintf(log_buffer + offset, sizeof(log_buffer) - offset, \
                                       "0x%lx", (unsigned long)args[i]);        \
                }                                                               \
            } else if (types[i] == ARG_PTR) {                                   \
                /* opaque pointer: printed, NOT copied (shape/direction unknown)*/ \
                offset += snprintf(log_buffer + offset, sizeof(log_buffer) - offset, \
                                   "0x%lx", (unsigned long)args[i]);            \
            } else {                                                            \
                offset += snprintf(log_buffer + offset, sizeof(log_buffer) - offset, \
                                   "%ld", (long)args[i]);                       \
            }                                                                   \
        }                                                                       \
                                                                                \
        offset += snprintf(log_buffer + offset, sizeof(log_buffer) - offset, ")"); \
                                                                                \
        /*                                                                      \
         * ABI CHANGE 3 — make_threei_call is 4-arg:                            \
         *   (nr, primary_cage, arg_cage[6], args[6])                           \
         * primary_cage is the TARGET cage (drives thread-op / mm-op routing).  \
         */                                                                     \
        ret = make_threei_call((uint32_t)(num), cageid, arg_cage, fwd);         \
                                                                                \
        for (int i = 0; i < 6; i++)                                             \
            free(strbuf[i]);                                                    \
                                                                                \
        fprintf(stderr, "%s = %ld\n", log_buffer, ret);                         \
        return ret;                                                             \
    }                                                                           \
                                                                                \
    /* constructor to store handler address in the table */                     \
    __attribute__((constructor)) static void register_##name(void) {            \
        syscall_handler_table[num] = &name##_grate;                             \
    }

#endif
