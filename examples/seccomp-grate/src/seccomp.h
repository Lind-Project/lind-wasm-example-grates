#ifndef SECCOMP_H
#define SECCOMP_H

#include <errno.h>
#include <lind_syscall.h>
#include <stdint.h>

#define MAX_SYSCALLS 334

typedef enum {
  MODE_UNASSIGNED = -1, // Catches entries before a section header
  WL = 0,               // Whitelist
  BL = 1,               // Blacklist
  MODE_DEFAULT = 2      // Internal parser state for the [default] section
} seccomp_mode_t;

// function ptr for storing syscall handlers
typedef int (*syscall_handler_t)(uint64_t cageid, uint64_t arg1,
                                 uint64_t arg1cage, uint64_t arg2,
                                 uint64_t arg2cage, uint64_t arg3,
                                 uint64_t arg3cage, uint64_t arg4,
                                 uint64_t arg4cage, uint64_t arg5,
                                 uint64_t arg5cage, uint64_t arg6,
                                 uint64_t arg6cage);

// syscall handler table
extern syscall_handler_t syscall_handler_table[MAX_SYSCALLS];

// lookup mapping structure
typedef struct {
  const char *name;
  int num;
} syscall_entry_t;

// array to track list type
extern seccomp_mode_t syscall_mode[MAX_SYSCALLS];

// handler for blacklisted syscalls
int blacklist_handler(uint64_t cageid, uint64_t arg1, uint64_t arg1cage,
                      uint64_t arg2, uint64_t arg2cage, uint64_t arg3,
                      uint64_t arg3cage, uint64_t arg4, uint64_t arg4cage,
                      uint64_t arg5, uint64_t arg5cage, uint64_t arg6,
                      uint64_t arg6cage);

// helper function to clean whitespaces
char *trim_whitespace(char *str);

// function to parse INI config file
void parse_config(const char *filename);

#endif
