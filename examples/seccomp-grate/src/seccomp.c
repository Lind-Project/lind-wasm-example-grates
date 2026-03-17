#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "seccomp.h"

// table for storing syscall handlers
syscall_handler_t syscall_handler_table[MAX_SYSCALLS] = {0};

// initializing tracing (disabled by default)
// can be enabled in cages by setting it to 1
int tracing_enabled = 0;

// defined syscall handlers
//
// args:
//      1st:            syscall name
//      2nd:            syscall number
//      3rd:            List type (BL | WL)
//
// defines handler for all syscalls supported by lind

// define seccomp filter for whitelisting 
// mkdir() syscall
DEFINE_FILTER(mkdir, 83, WL)

// define seccomp filter for blacklisting
// rmdir() syscall
DEFINE_FILTER(rmdir, 84, BL)
	
// dispatcher function
int pass_fptr_to_wt(uint64_t fn_ptr_uint, uint64_t cageid,
                    uint64_t arg1, uint64_t arg1cage, 
                    uint64_t arg2, uint64_t arg2cage,
                    uint64_t arg3, uint64_t arg3cage, 
                    uint64_t arg4, uint64_t arg4cage,
                    uint64_t arg5, uint64_t arg5cage, 
                    uint64_t arg6, uint64_t arg6cage) {

    if (fn_ptr_uint == 0) {
        return -1;
    }

    syscall_handler_t fn = (syscall_handler_t)(uintptr_t)fn_ptr_uint;

    return fn(cageid, arg1, arg1cage, arg2, arg2cage, arg3, arg3cage, 
              arg4, arg4cage, arg5, arg5cage, arg6, arg6cage);
}
