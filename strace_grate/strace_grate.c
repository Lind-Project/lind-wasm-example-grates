#include <errno.h>
#include <register_handler.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <lind_syscall.h>

// Helper function to get syscall name from number
static const char* get_syscall_name(uint64_t syscall_num) {
  // simplified mapping - in a real implementation, we want
  // a complete mapping of all syscall numbers to names
  switch (syscall_num) {
    case 0: return "read";
    case 1: return "write";
    case 2: return "open";
    case 3: return "close";
    case 107: return "geteuid";
    // Add more syscalls as needed
    default: return "unknown";
  }
}

// Wrapper function type for syscall handlers
// Each wrapper knows its syscall number and calls strace_grate with it
typedef int (*strace_wrapper_t)(uint64_t cageid, uint64_t arg1, uint64_t arg2,
                                 uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6);

// Dispatcher function - same signature as geteuid_grate for compatibility
int pass_fptr_to_wt(uint64_t fn_ptr_uint, uint64_t cageid, uint64_t arg1,
                    uint64_t arg1cage, uint64_t arg2, uint64_t arg2cage,
                    uint64_t arg3, uint64_t arg3cage, uint64_t arg4,
                    uint64_t arg4cage, uint64_t arg5, uint64_t arg5cage,
                    uint64_t arg6, uint64_t arg6cage) {
  if (fn_ptr_uint == 0) {
    fprintf(stderr, "[Grate|strace] Invalid function ptr\n");
    return -1;
  }

  printf("[Grate|strace] Handling function ptr: %llu from cage: %llu\n",
         fn_ptr_uint, cageid);

  // The function pointer points to a wrapper that knows its syscall number
  // and calls strace_grate with it
  strace_wrapper_t fn = (strace_wrapper_t)(uintptr_t)fn_ptr_uint;

  return fn(cageid, arg1, arg2, arg3, arg4, arg5, arg6);
}

// Main strace_grate function that handles syscall interception
// This function receives the syscall number and arguments, prints them,
// executes the syscall, and prints the return value
static int strace_grate_impl(uint64_t cageid, uint64_t syscall_number, uint64_t arg1,
                             uint64_t arg2, uint64_t arg3, uint64_t arg4,
                             uint64_t arg5, uint64_t arg6) {
  const char* syscall_name = get_syscall_name(syscall_number);
  
  // Print syscall name, number, and arguments (as pointers)
  printf("[Grate|strace] Syscall: %s (number: %llu)\n", syscall_name, syscall_number);
  printf("[Grate|strace] Arguments (as pointers): %llu, %llu, %llu, %llu, %llu, %llu\n",
         (unsigned long long)arg1, (unsigned long long)arg2, (unsigned long long)arg3,
         (unsigned long long)arg4, (unsigned long long)arg5, (unsigned long long)arg6);
  
  // Execute the syscall using lind_syscall
  // lind_syscall signature: (callnumber, callname, arg1, arg2, arg3, arg4, arg5, arg6, raw)
  // callname is typically 0 or a pointer to the syscall name
  int ret = lind_syscall((unsigned int)syscall_number, 0, arg1, arg2, arg3, arg4, arg5, arg6, 0);
  
  // Print the return value after execution
  printf("[Grate|strace] Return value: %d\n", ret);
  
  // Return the return value of the syscall
  return ret;
}

// Macro to generate wrapper functions for each syscall
// Each wrapper knows its syscall number and calls strace_grate_impl with it
#define SYSCALL_WRAPPER(num) \
  static int strace_wrapper_##num(uint64_t cageid, uint64_t arg1, uint64_t arg2, \
                                   uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6) { \
    return strace_grate_impl(cageid, num, arg1, arg2, arg3, arg4, arg5, arg6); \
  }

// Generate wrappers for common syscalls
SYSCALL_WRAPPER(0)   // read
SYSCALL_WRAPPER(1)   // write
SYSCALL_WRAPPER(2)   // open
SYSCALL_WRAPPER(3)   // close
SYSCALL_WRAPPER(107) // geteuid
// Add more syscalls as needed

// Helper function to get the wrapper function pointer for a syscall number
static uint64_t get_wrapper_for_syscall(uint64_t syscall_num) {
  switch (syscall_num) {
    case 0: return (uint64_t)(uintptr_t)&strace_wrapper_0;
    case 1: return (uint64_t)(uintptr_t)&strace_wrapper_1;
    case 2: return (uint64_t)(uintptr_t)&strace_wrapper_2;
    case 3: return (uint64_t)(uintptr_t)&strace_wrapper_3;
    case 107: return (uint64_t)(uintptr_t)&strace_wrapper_107;
    default: return 0; // Unknown syscall
  }
}

// Main function will always be same in all grates
int main(int argc, char *argv[]) {
  // Should be at least two inputs (at least one grate file and one cage file)
  if (argc < 2) {
    fprintf(stderr, "Usage: %s <cage_file> <grate_file> <cage_file> [...]\n",
            argv[0]);
    exit(EXIT_FAILURE);
  }

  int grateid = getpid();

  // Because we assume that all cages are unaware of the existence of grate,
  // cages will not handle the logic of `exec`ing grate, so we need to handle
  // these two situations separately in grate. grate needs to fork in two
  // situations:
  // - the first is to fork and use its own cage;
  // - the second is when there is still at least one grate in the subsequent
  // command line input. In the second case, we fork & exec the new grate and
  // let the new grate handle the subsequent process.
  for (int i = 1; i < (argc < 3 ? argc : 3); i++) {
    pid_t pid = fork();
    if (pid < 0) {
      perror("fork failed");
      exit(EXIT_FAILURE);
    } else if (pid == 0) {
      // According to input format, the odd-numbered positions will always be
      // grate, and even-numbered positions will always be cage.
      if (i % 2 != 0) {
        // Next one is cage, only set the register_handler when next one is cage
        int cageid = getpid();
        
        // Register handlers for all syscalls we want to trace
        // List of syscall numbers to intercept
        uint64_t syscall_numbers[] = {0, 1, 2, 3, 107}; // read, write, open, close, geteuid
        int num_syscalls = sizeof(syscall_numbers) / sizeof(syscall_numbers[0]);
        
        for (int j = 0; j < num_syscalls; j++) {
          uint64_t syscall_num = syscall_numbers[j];
          uint64_t fn_ptr_addr = get_wrapper_for_syscall(syscall_num);
          
          if (fn_ptr_addr == 0) {
            fprintf(stderr, "[Grate|strace] No wrapper for syscall %llu\n", syscall_num);
            continue;
          }
          
          printf("[Grate|strace] Registering strace handler for syscall %llu "
                 "for cage %d in grate %d with fn ptr addr: %llu\n",
                 syscall_num, cageid, grateid, fn_ptr_addr);
          int ret = register_handler(cageid, syscall_num, 1, grateid, fn_ptr_addr);
          if (ret != 0) {
            fprintf(stderr, "[Grate|strace] Failed to register handler for syscall %llu\n", syscall_num);
          }
        }
      }

      if (execv(argv[i], &argv[i]) == -1) {
        perror("execv failed");
        exit(EXIT_FAILURE);
      }
    }
  }

  int status;
  while (wait(&status) > 0) {
    printf("[Grate|strace] terminated, status: %d\n", status);
  }

  return 0;
}
  