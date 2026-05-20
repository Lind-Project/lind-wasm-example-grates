#include <errno.h>
#include <lind_syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define GETPID_SYSCALL 39

int pass_fptr_to_wt(uint64_t fn_ptr_uint, uint64_t grateid, uint64_t arg1,
                    uint64_t arg1cage, uint64_t arg2, uint64_t arg2cage,
                    uint64_t arg3, uint64_t arg3cage, uint64_t arg4,
                    uint64_t arg4cage, uint64_t arg5, uint64_t arg5cage,
                    uint64_t arg6, uint64_t arg6cage) {
  if (fn_ptr_uint == 0) {
    return -1;
  }

  int (*fn)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
            uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
            uint64_t) =
      (int (*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
               uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
               uint64_t))(uintptr_t)fn_ptr_uint;

  return fn(grateid, arg1, arg1cage, arg2, arg2cage, arg3, arg3cage, arg4,
            arg4cage, arg5, arg5cage, arg6, arg6cage);
}

int getpid_grate(uint64_t cageid, uint64_t arg1, uint64_t arg1cage,
                 uint64_t arg2, uint64_t arg2cage, uint64_t arg3,
                 uint64_t arg3cage, uint64_t arg4, uint64_t arg4cage,
                 uint64_t arg5, uint64_t arg5cage, uint64_t arg6,
                 uint64_t arg6cage) {

  return make_threei_call(GETPID_SYSCALL, 0, cageid, arg1cage, arg1,
                          arg1cage, arg2, arg2cage, arg3, arg3cage, arg4,
                          arg4cage, arg5, arg5cage, arg6, arg6cage, 0);
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    printf("Usage: %s <cage_file>\n", argv[0]);
    exit(EXIT_FAILURE);
  }
  int grateid = getpid();

  pid_t pid = fork();
  if (pid < 0) {
    perror("fork failed");
    exit(EXIT_FAILURE);
  } else if (pid == 0) {
    int cageid = getpid();
    
    uint64_t fn_ptr_addr = (uint64_t)(uintptr_t)&getpid_grate;
    int ret = register_handler(cageid, GETPID_SYSCALL, grateid, fn_ptr_addr);

    if (execv(argv[1], &argv[1]) == -1) {
      perror("execv failed");
      exit(EXIT_FAILURE);
    }
  }

  int status;
  while (wait(&status) > 0) {
    printf("[Grate|getpid] terminated, status: %d\n", status);
  }

  return 0;
}
