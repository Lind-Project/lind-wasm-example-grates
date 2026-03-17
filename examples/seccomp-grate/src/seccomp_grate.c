#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <semaphore.h>
#include <sys/mman.h>
#include "seccomp.h"

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <cage_binary> [args...]\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    
    // using semaphores for synchronizing the grate and cage.
    //
    // this ensures that all the initalization is done by the grate.
    sem_t *sem = mmap(NULL, sizeof(*sem), PROT_READ | PROT_WRITE,
		      MAP_SHARED | MAP_ANON, -1, 0);

    int grateid = getpid();
    pid_t cageid = fork();

    if (cageid < 0) {
        perror("fork failed");
        exit(EXIT_FAILURE);
    } else if (cageid == 0) {
	// wait for grate to register handlers
        sem_wait(sem);
	
	if (execv(argv[1], &argv[1]) == -1) {
            perror("execv failed");
            exit(EXIT_FAILURE);
        }
    }

    // loop to register syscall handlers
    for (int i = 0; i < MAX_SYSCALLS; i++) {
        if (syscall_handler_table[i] != NULL) {
            uint64_t fn_ptr = (uint64_t)(uintptr_t)syscall_handler_table[i];
                register_handler(cageid, i, grateid,  fn_ptr);
	}
    }
    
    // resume execution of the cage
    sem_post(sem);

    int status;
    int w;
    
    while (1) {
	w = wait(&status);
	if (w > 0) {
	    break;
	}
    }
    
    sem_destroy(sem);
    munmap(sem, sizeof(*sem));
    
    return 0;
}
