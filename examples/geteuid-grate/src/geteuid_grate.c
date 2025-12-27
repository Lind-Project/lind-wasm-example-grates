#include <errno.h>
#include <lind_syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

// Dispatcher function
int pass_fptr_to_wt(uint64_t fn_ptr_uint, uint64_t cageid, uint64_t arg1,
                    uint64_t arg1cage, uint64_t arg2, uint64_t arg2cage,
                    uint64_t arg3, uint64_t arg3cage, uint64_t arg4,
                    uint64_t arg4cage, uint64_t arg5, uint64_t arg5cage,
                    uint64_t arg6, uint64_t arg6cage) {
  if (fn_ptr_uint == 0) {
    fprintf(stderr, "[Grate|geteuid] Invalid function ptr\n");
    return -1;
  }

  printf("[Grate|geteuid] Handling function ptr: %llu from cage: %llu\n",
         fn_ptr_uint, cageid);

  int (*fn)(uint64_t) = (int (*)(uint64_t))(uintptr_t)fn_ptr_uint;

  return fn(cageid);
}

// Function ptr and signatures of this grate
int geteuid_grate(uint64_t);

int geteuid_grate(uint64_t cageid) {
  printf("[Grate|geteuid] In geteuid_grate %d handler for cage: %llu\n",
         getpid(), cageid);
  return 10;
}

// Main function will always be same in all grates
int main(int argc, char *argv[]) {
  // Should be at least two inputs (at least one grate file and one cage file)
  if (argc < 2) {
    fprintf(stderr, "Usage: %s <cage_file>\n", argv[0]);
    exit(EXIT_FAILURE);
  }

  int grateid = getpid();

  // Because we assume that all cages are unaware of the existence of grate,
  // cages will not handle the logic of `exec`ing grate.
  // Instead, a grate instance is responsible for mananging this.
  //
  // It forks and execs exactly once: To execute the child binary provided
  // as argv[1], passing argv[1..] as that program's command-line arguments.
  // Any further process management is handled by this executed program, not
  // by the original grate.

  pid_t pid = fork();
  if (pid < 0) {
    perror("fork failed");
    exit(EXIT_FAILURE);
  } else if (pid == 0) {
    int cageid = getpid();
    // Set the geteuid (syscallnum=107) of this cage to call this grate
    // function geteuid_grate (func index=0)
    // Syntax of register_handler:
    //   register_handler(
    //     int64_t targetcage, - Cage ID to be intercepted
    //     uint64_t targetcallnum, - Syscall number to be intercepted
    //     uint64_t handlefunc_flag, - 0 for deregister non-0 for register
    //     uint64_t this_grate_id, - Grate ID to redirect call to
    //     uint64_t optional_arg - Handler function pointer if registering
    //   )
    uint64_t fn_ptr_addr = (uint64_t)(uintptr_t)&geteuid_grate;
    printf("[Grate|geteuid] Registering geteuid handler for cage %d in "
           "grate %d with fn ptr addr: %llu\n",
           cageid, grateid, fn_ptr_addr);
    int ret = register_handler(cageid, 107, 1, grateid, fn_ptr_addr);

    if (execv(argv[1], &argv[1]) == -1) {
      perror("execv failed");
      exit(EXIT_FAILURE);
    }
  }

  int status;
  while (wait(&status) > 0) {
    printf("[Grate|geteuid] terminated, status: %d\n", status);
  }

  return 0;
}
