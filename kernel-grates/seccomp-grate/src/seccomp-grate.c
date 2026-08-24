#include "seccomp.h"
#include <semaphore.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 * seccomp grate — converted to the current 3i C ABI.
 *
 * Reads a whitelist/blacklist policy, then registers blacklist_handler (which
 * returns -EPERM) for every BLACKLISTED syscall. A blacklisted syscall the cage
 * makes is intercepted and denied.
 *
 * ABI changes: handler signature (in seccomp.h/.c), pass_fptr_to_wt removed,
 * syscall numbers are kernel __NR_* (via syscalls.h), <lind_syscall.h> ->
 * <threei.h>.
 */
int main(int argc, char *argv[]) {
  if (argc < 3) {
    fprintf(stderr, "Usage: %s <seccomp-config.conf> <cage_binary> [args...]\n", argv[0]);
    exit(EXIT_FAILURE);
  }

  parse_config(argv[1]);

  sem_t *sem = mmap(NULL, sizeof(*sem), PROT_READ | PROT_WRITE,
                    MAP_SHARED | MAP_ANON, -1, 0);
  sem_init(sem, 1, 0);

  pid_t grateid = getpid();
  pid_t cageid = fork();
  if (cageid < 0) { perror("fork failed"); exit(EXIT_FAILURE); }

  if (cageid == 0) {
    sem_wait(sem);                     /* wait for the grate to register */
    if (execv(argv[2], &argv[2]) == -1) { perror("execv failed"); exit(EXIT_FAILURE); }
  }

  /* register blacklist_handler for every blacklisted syscall (kernel numbers) */
  for (int i = 0; i < MAX_SYSCALLS; i++) {
    if (syscall_mode[i] == BL) {
      register_handler(cageid, (unsigned)i, grateid,
                       (unsigned long)&blacklist_handler);
    }
  }

  sem_post(sem);                       /* let the cage exec */

  int status;
  wait(&status);

  sem_destroy(sem);
  munmap(sem, sizeof(*sem));

}
