#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
#include <semaphore.h>
#include <sys/mman.h>

#include "strace.c"

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

    sem_init(sem, 1, 0);

    int grateid = getpid();
    pid_t cageid = fork();

    if (cageid < 0) {
        perror("fork failed");
        exit(EXIT_FAILURE);
    } else if (cageid == 0) {
        // wait for grate to register handlers
        sem_wait(sem);

        execv(argv[1], &argv[1]);
        /* only reached if execv failed; do NOT fall through into grate code */
        perror("execv failed");
        _exit(127);
    }

    // loop to register syscall handlers
    for (int i = 0; i < MAX_SYSCALLS; i++) {
        if (syscall_handler_table[i] != NULL) {
            unsigned long fn_ptr = (unsigned long)(uintptr_t)syscall_handler_table[i];
            register_handler(cageid, (uint32_t)i, grateid, fn_ptr);
        }
    }

    // resume execution of the cage
    sem_post(sem);

    int status;

    wait(&status);

    sem_destroy(sem);
    munmap(sem, sizeof(*sem));

    return 0;
}
