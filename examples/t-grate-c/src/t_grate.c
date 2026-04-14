#include <lind_syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <stdint.h>
#include <sys/wait.h>
#include <unistd.h>

#include "tee.h"
#include "handlers.h"

#define LOG(...) printf(__VA_ARGS__);

int pass_fptr_to_wt(uint64_t fn_ptr_uint, uint64_t grateid, uint64_t arg1,
		    uint64_t arg1cage, uint64_t arg2, uint64_t arg2cage,
		    uint64_t arg3, uint64_t arg3cage, uint64_t arg4,
		    uint64_t arg4cage, uint64_t arg5, uint64_t arg5cage,
		    uint64_t arg6, uint64_t arg6cage) {
	if (fn_ptr_uint == 0) {
		LOG("[t-grate|grate] Invalid function ptr\n");
		return -1;
	}

	int cage_id = arg1cage;

	LOG("[t-grate|grate] Handling function ptr: %llu from cage: %d\n",
	    fn_ptr_uint, cage_id);

	int (*fn)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
		  uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
		  uint64_t) =
	    (int (*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
		     uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
		     uint64_t))(uintptr_t)fn_ptr_uint;

	return fn(grateid, arg1, arg1cage, arg2, arg2cage, arg3, arg3cage, arg4,
		  arg4cage, arg5, arg5cage, arg6, arg6cage);

}

char **rewrite_argv(char **argv, int argc, int *primary_start, int *secondary_start, int *target_start) {
    char **newv = malloc((argc + 2) * sizeof(char *));
    int j = 0;

    *primary_start = *secondary_start = *target_start = -1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "%{") == 0) {
            if (*primary_start == -1) *primary_start = j;
            else if (*secondary_start == -1) *secondary_start = j;
            continue;
        }

        if (*secondary_start == -1 && strcmp(argv[i], "%}") == 0)
            *secondary_start = j + 1;
        else if (*target_start == -1 && *secondary_start != -1 && strcmp(argv[i], "%}") == 0)
            *target_start = j + 1;

        newv[j++] = argv[i];

        if (strcmp(argv[i], "%}") == 0)
            newv[j++] = NULL;
    }

    newv[j] = NULL;
    *secondary_start = *secondary_start + 1;
    *target_start = *target_start + 1;
    return newv;
}

// argv: t-grate %{ primary %} %{   secondary %}               test
// newv: -       -  ps         NULL ss          NULL(inserted) ts 
int main(int argc, char *argv[]) {
    int ps, ss, ts;
    char **newv_p = rewrite_argv(argv, argc, &ps, &ss, &ts);
    

    int tee_cageid = getpid();
    // int *tee_cageid = malloc(sizeof(int)); *tee_cageid = getpid();

    TEESTATE.primary_done = mmap(NULL, sizeof(*TEESTATE.primary_done),
    PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
    
    if (TEESTATE.primary_done == MAP_FAILED) { perror("mmap primary_done"); exit(1); }
    
    TEESTATE.secondary_done = mmap(NULL, sizeof(*TEESTATE.secondary_done),
	    PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
    
    if (TEESTATE.secondary_done == MAP_FAILED) { perror("mmap secondary_done"); exit(1); }

    TEESTATE.exiting = mmap(NULL, sizeof(*TEESTATE.exiting),
	    PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
    
    if (TEESTATE.exiting == MAP_FAILED) { perror("mmap exiting"); exit(1); }

    if (sem_init(TEESTATE.primary_done, 1, 0) < 0) { perror("sem_init primary_done"); exit(1); }
    if (sem_init(TEESTATE.secondary_done, 1, 0) < 0) { perror("sem_init secondary_done"); exit(1); }
    if (sem_init(TEESTATE.exiting, 1, 0) < 0) { perror("sem_init exiting"); exit(1); }

    int primary_stack = fork();
    if (primary_stack < 0) {
        printf("[t-grate] fork failed\n");
        exit(0);
    } else if (primary_stack == 0) {
        // Primary stack. 
        int cageid = getpid();

        register_handler(cageid, 59, tee_cageid, (uint64_t)&exec_handler);

        printf("\n[t-grate | primary] path: %s\n", newv_p[ps]);
        int ret = execv(newv_p[ps], &newv_p[ps]);
        printf("[t-grate | primary] exec returned: %d\n", ret);
        exit(0);
    }

    printf("[t-grate] waiting for primary stack.\n");
    sem_wait(TEESTATE.primary_done);
    printf("[t-grate] waitedfor primary stack.\n");
  
    printf("\nps=%d ss=%d ts=%d\n", ps, ss, ts);

    int secondary_stack = fork();
    if (secondary_stack  < 0) {
        printf("[t-grate] fork failed\n");
        exit(0);
    } else if (secondary_stack == 0) {
        // Secondary stack.
        int cageid = getpid();
        printf("\n[t-grate | secondary] cageid:%d\n", cageid);
        printf("   tee_cageid: %d\n", tee_cageid);
        printf("   path: %s\n", newv_p[ss]);
       
        register_handler(cageid, 59, tee_cageid, (uint64_t)&exec_handler);
        
        printf("[t-grate | secondary] execing...\n");
        int ret = execv(newv_p[ss], &newv_p[ss]);
        printf("[t-grate | secondary] exec returned: %d\n", ret);
        exit(0);
    }

    printf("[t-grate] waiting for secondary stack.\n");
    sem_wait(TEESTATE.secondary_done);
    printf("[t-grate] waitedfor secondary stack.\n");
   
    sem_t *target_sem = mmap(NULL, sizeof(*target_sem), PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_ANON, -1, 0);

    sem_init(target_sem, 1, 0);

    int target_stack = fork();
    if (target_stack < 0) {
        printf("[t-grate] fork failed");
        exit(0);
    } else if (target_stack == 0) {
        // Target stack.
    
        sem_wait(target_sem);

        printf("\n[t-grate | target] path: %s\n", newv_p[ts]);
        int ret = execv(newv_p[ts], &newv_p[ts]);
        printf("[t-grate | target] exec returned: %d\n", ret);
        exit(0);
    }

    // Do things here...
    sem_post(target_sem);

    pid_t pid;
    while ((pid = waitpid(-1, NULL, 0)) > 0) {
        printf("[t-grate] child exited: %d\n", pid);
    }

    return 0;
}


