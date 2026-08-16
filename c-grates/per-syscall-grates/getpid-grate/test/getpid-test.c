#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <assert.h>

int main() {
    pid_t pid1, pid2;

    // 1. Multiple calls should return the same PID
    pid1 = getpid();
    pid2 = getpid();
    assert(pid1 == pid2);

    // 2. PID should be positive
    assert(pid1 > 0);

    // 3. Fork and verify child has a different PID
    pid_t child = fork();
    assert(child >= 0);

    if (child == 0) {
        // Child process
        pid_t child_pid = getpid();
        pid_t parent_pid = getppid();

        assert(child_pid != pid1);   // child PID differs from parent
        assert(parent_pid == pid1);  // parent PID matches original

        _exit(0);
    } else {
        // Parent process
        int status;
        waitpid(child, &status, 0);
        assert(WIFEXITED(status));
    }

    printf("getpid() test passed (pid=%d)\n", pid1);
    return 0;
}
