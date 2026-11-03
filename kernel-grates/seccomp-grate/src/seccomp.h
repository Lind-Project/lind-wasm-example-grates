#ifndef SECCOMP_H
#define SECCOMP_H

#include <errno.h>
#include <stdint.h>
#include <sys/types.h> /* pid_t */

#define MAX_SYSCALLS 334

typedef enum {
	MODE_UNASSIGNED = -1, /* Catches entries before a section header */
	WL = 0,		      /* Whitelist */
	BL = 1,		      /* Blacklist */
	MODE_DEFAULT = 2      /* Internal parser state for the [default] section */
} seccomp_mode_t;

/*
 * 3i syscall handler ABI: the primary (calling) cage, the per-argument owning
 * cages, and the six syscall arguments. (Was the flattened lind
 * (cageid, arg1, arg1cage, ...) form.)
 */
typedef long (*syscall_handler_t)(pid_t cage, const int arg_cage[6],
				  unsigned long args[6]);

/* lookup mapping structure */
typedef struct {
	const char *name;
	int num;
} syscall_entry_t;

/* array to track list type */
extern seccomp_mode_t syscall_mode[MAX_SYSCALLS];

/* handler for blacklisted syscalls: denies with -EPERM */
long blacklist_handler(pid_t cage, const int arg_cage[6], unsigned long args[6]);

/* helper function to clean whitespaces */
char *trim_whitespace(char *str);

/* function to parse INI config file */
void parse_config(const char *filename);

#endif
