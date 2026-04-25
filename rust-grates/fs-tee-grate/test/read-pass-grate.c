#include <errno.h>
#include <lind_syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <assert.h>

// Dispatcher function
int pass_fptr_to_wt(uint64_t fn_ptr_uint, uint64_t cageid, uint64_t arg1,
                    uint64_t arg1cage, uint64_t arg2, uint64_t arg2cage,
                    uint64_t arg3, uint64_t arg3cage, uint64_t arg4,
                    uint64_t arg4cage, uint64_t arg5, uint64_t arg5cage,
                    uint64_t arg6, uint64_t arg6cage) {
  if (fn_ptr_uint == 0) {
    fprintf(stderr, "[grate-pass|read] Invalid function ptr\n");
    assert(0);
  }



  printf("[grate-pass|read] Handling function ptr: %llu from cage: %llu\n",
         fn_ptr_uint, cageid);

   int (*fn)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
              uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
              uint64_t, uint64_t, uint64_t) =
        (int (*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                 uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                 uint64_t, uint64_t, uint64_t))(uintptr_t)fn_ptr_uint;

    return fn(cageid, arg1, arg1cage, arg2, arg2cage,
              arg3, arg3cage, arg4, arg4cage,
              arg5, arg5cage, arg6, arg6cage);

}

int read_grate(uint64_t cageid, uint64_t arg1, uint64_t arg1cage,uint64_t arg2, uint64_t arg2cage,uint64_t arg3, uint64_t arg3cage,uint64_t arg4, uint64_t arg4cage,uint64_t arg5, uint64_t arg5cage,uint64_t arg6, uint64_t arg6cage) {
  printf("[grate-pass|read] In read_grate %d handler for cage: %llu\n",
         getpid(), arg1cage);
  
  return make_threei_call(
	0, 
	0, 
	cageid,
	arg1cage,
	arg1, arg1cage,
	arg2, arg2cage,
	arg3, arg3cage,
	arg4, arg4cage,
	arg5, arg5cage,
	arg6, arg6cage,
  	0
  ) * 2 + 4;
}

// Main function will always be same in all grates
int main(int argc, char *argv[]) {
  printf("[grate-pass|read] Init...\n");
  // Should be at least two inputs (at least one grate file and one cage file)
  if (argc < 2) {
    fprintf(stderr, "Usage: %s <cage_file> <grate_file> <cage_file> [...]\n",
            argv[0]);
    assert(0);
  }

  int grateid = getpid();

  pid_t pid = fork();
  printf("[grate-pass|read] Fork: %d\n", pid);
  if (pid < 0) {
    perror("fork failed");
    assert(0);
  } else if (pid == 0) {
    int cageid = getpid();
  
    uint64_t fn_ptr_addr = (uint64_t)(uintptr_t)&read_grate;
    printf("[grate-pass|read] Registering read handler for cage %d in "
            "grate %d with fn ptr addr: %llu\n",
            cageid, grateid, fn_ptr_addr);
   
    int ret = register_handler(cageid, 0, grateid, fn_ptr_addr);
    if (ret != 0) {
      fprintf(stderr, "[grate-pass|read] Failed to register handler for cage %d in "
              "grate %d with fn ptr addr: %llu, ret: %d\n",
              cageid, grateid, fn_ptr_addr, ret);
      assert(0);
    }

    if (execv(argv[1], &argv[1]) == -1) {
      perror("execv failed");
      assert(0);
    }
  }

  int status;
  int failed = 0;
  while (wait(&status) > 0) {
    if (status != 0) {
      fprintf(stderr, "[grate-pass|read] FAIL: child exited with status %d\n", status);
      assert(0);
    }
  }

  printf("[grate-pass|read] PASS\n");
  return 0;
}
