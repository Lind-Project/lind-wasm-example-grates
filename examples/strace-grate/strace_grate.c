#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
#include "strace.h"

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <cage_binary> [args...]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int grateid = getpid();
    pid_t pid = fork();

    if (pid < 0) {
        perror("fork failed");
        exit(EXIT_FAILURE);
    } else if (pid == 0) {
        int cageid = getpid();

        // loop to register syscall handlers
        for (int i = 0; i < MAX_SYSCALLS; i++) {
            if (syscall_handler_table[i] != NULL) {
                uint64_t fn_ptr = (uint64_t)(uintptr_t)syscall_handler_table[i];
                register_handler(cageid, i, 1, grateid, fn_ptr);
            	//fprintf(stderr, "[Grate] Registered handler for syscall %d at 0x%llx\n", i, fn_ptr);
	  }
        }
        if (execv(argv[1], &argv[1]) == -1) {
            perror("execv failed");
            exit(EXIT_FAILURE);
        }
    }

    int status;
    while (wait(&status) > 0) {
        fprintf(stderr, "[Grate] process terminated, status: %d\n", status);
    }
    return 0;
}
