#ifndef SECCOMP_H
#define SECCOMP_H

#include <errno.h>
#include <stdint.h>
#include <sys/types.h>

#include <threei.h>        /* current 3i ABI (was lind_syscall.h) */

#define MAX_SYSCALLS 512   /* must exceed the largest kernel __NR_* we register */

typedef enum {
  MODE_UNASSIGNED = -1, /* entries before a section header */
  WL = 0,               /* whitelist */
  BL = 1,               /* blacklist */
  MODE_DEFAULT = 2      /* internal parser state for [default] */
} seccomp_mode_t;

/* current 3i handler signature (was the lind 13-arg form) */
typedef long (*syscall_handler_t)(pid_t cageid, const int arg_cage[6],
                                  unsigned long args[6]);

typedef struct {
  const char *name;
  int num;
} syscall_entry_t;

extern seccomp_mode_t syscall_mode[MAX_SYSCALLS];

/* handler for blacklisted syscalls: denies with -EPERM */
long blacklist_handler(pid_t cageid, const int arg_cage[6],
                       unsigned long args[6]);

char *trim_whitespace(char *str);
void parse_config(const char *filename);

#endif
