#ifndef STRACE_H
#define STRACE_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <lind_syscall.h>

#define ARG_INT 0
#define ARG_STR 1
#define ARG_PTR 2
#define MAX_SYSCALLS 334

extern int tracing_enabled;

// function ptr for storing syscall handlers
typedef int (*syscall_handler_t)(uint64_t, uint64_t, uint64_t, uint64_t,
                                 uint64_t, uint64_t, uint64_t, uint64_t,
                                 uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

// table for storing syscall handlers
extern syscall_handler_t syscall_handler_table[MAX_SYSCALLS];

// macro for defining syscall handlers dynamically
#define DEFINE_HANDLER(name, num, ...)                                          \
    /* function defination for syscall handler */                               \
    int name##_grate(uint64_t cageid, uint64_t arg1, uint64_t arg1cage,         \
                     uint64_t arg2, uint64_t arg2cage,                          \
                     uint64_t arg3, uint64_t arg3cage,                          \
                     uint64_t arg4, uint64_t arg4cage,                          \
                     uint64_t arg5, uint64_t arg5cage,                          \
                     uint64_t arg6, uint64_t arg6cage) {                        \
                                                                                \
        int thiscage = getpid();                                                \
        int types[] = {__VA_ARGS__};                                            \
        int argsnum = sizeof(types) / sizeof(int);                              \
        uint64_t args[] = {arg1, arg2, arg3, arg4, arg5, arg6};                \
        uint64_t argcages[] = {arg1cage, arg2cage, arg3cage, arg4cage,          \
                               arg5cage, arg6cage};                             \
                                                                                \
        char log_buffer[1024];                                                  \
        int offset = 0;                                                         \
                                                                                \
        /* log buffer to print syscall with args and ret val */                 \
        offset += snprintf(log_buffer + offset, 1024 - offset, "%s(", #name);   \
                                                                                \
        for (int i = 0; i < argsnum; i++) {                                     \
            if (i > 0)                                                          \
                offset += snprintf(log_buffer + offset, 1024 - offset, ", ");   \
                                                                                \
            if (types[i] == ARG_STR && args[i] != 0) {                          \
                char *buf = malloc(256);                                        \
                if (buf) {                                                      \
                    copy_data_between_cages(thiscage, argcages[i],              \
                                            args[i], argcages[i],               \
                                            (uint64_t)buf, thiscage,            \
                                            256, 1);                            \
                    offset += snprintf(log_buffer + offset, 1024 - offset,      \
                                       "\"%s\"", buf);                          \
                    free(buf);                                                  \
                } else {                                                        \
                    offset += snprintf(log_buffer + offset, 1024 - offset,      \
                                       "0x%lx", (unsigned long)args[i]);        \
                }                                                               \
            } else if (types[i] == ARG_PTR || args[i] > 0xFFFFFF || args[i] == 0) { \
                offset += snprintf(log_buffer + offset, 1024 - offset,          \
                                   "0x%lx", (unsigned long)args[i]);            \
            } else {                                                            \
                offset += snprintf(log_buffer + offset, 1024 - offset,          \
                                   "%ld", (long)args[i]);                       \
            }                                                                   \
        }                                                                       \
        offset += snprintf(log_buffer + offset, 1024 - offset, ")");            \
        									\
	/* flush log buffer before exit */		    			\
        int exit_call = (num == 60);               				\
        if (exit_call) {                    					\
            fprintf(stderr, "%s\n", log_buffer);                                \
            fflush(stderr);                                                     \
        }                                                                       \
                                                                                \
        /* forward interposed syscall */                                        \
        int ret = make_threei_call(num, 0,                                      \
                                   thiscage, arg1cage,                          \
                                   arg1, arg1cage, arg2, arg2cage,              \
                                   arg3, arg3cage, arg4, arg4cage,              \
                                   arg5, arg5cage, arg6, arg6cage, 0);          \
                                                                                \
        if (!exit_call) {                                               	\
            fprintf(stderr, "%s = %d\n", log_buffer, ret);                      \
        } else {                                                                \
            fprintf(stderr, "%s [failed] = %d\n", log_buffer, ret);             \
        }                                                                       \
                                                                                \
        /* printing log buffer after return to ensure proper printing */        \
        /*fprintf(stderr, "%s = %d\n", log_buffer, ret);*/                      \
        return ret;                                                             \
    }                                                                           \
                                                                                \
    /* constructor to store handler address in the table */                     \
    __attribute__((constructor)) static void register_##name() {                \
        syscall_handler_table[num] = &name##_grate;                             \
    }

#endif
