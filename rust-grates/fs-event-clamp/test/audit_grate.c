#include <lind_syscall.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

static int64_t deny_read(uint64_t cage) { return -166; }
static int64_t deny_write(uint64_t cage) { return -167; }
static int64_t deny_open(uint64_t cage) { return -168; }
static int64_t custom_syscall(uint64_t cage) { return 168; }
static int64_t late_syscall(uint64_t cage) { return 169; }

static int64_t audit_geteuid(uint64_t cage) {
    // Exercise a new runtime registration after the target has activated.
    int ret = register_handler(cage, 2049, getpid(), (uint64_t)(uintptr_t)late_syscall);
    return ret == 0 ? 166 : -1;
}

int64_t pass_fptr_to_wt(uint64_t fn, uint64_t grate, uint64_t arg1,
                       uint64_t arg1cage, uint64_t arg2, uint64_t arg2cage,
                       uint64_t arg3, uint64_t arg3cage, uint64_t arg4,
                       uint64_t arg4cage, uint64_t arg5, uint64_t arg5cage,
                       uint64_t arg6, uint64_t arg6cage) {
    return ((int64_t (*)(uint64_t))(uintptr_t)fn)(arg1cage);
}

int main(int argc, char **argv) {
    if (argc < 2)
        return 2;
    uint64_t grate = getpid();
    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        return 1;
    }
    if (child == 0) {
        struct {
            uint64_t nr;
            int64_t (*handler)(uint64_t);
        } handlers[] = {
            {0, deny_read}, {1, deny_write}, {2, deny_open}, {257, deny_open},
            {107, audit_geteuid}, {2048, custom_syscall},
        };
        for (size_t i = 0; i < sizeof(handlers) / sizeof(handlers[0]); ++i) {
            if (register_handler(getpid(), handlers[i].nr, grate,
                                 (uint64_t)(uintptr_t)handlers[i].handler) != 0) {
                fprintf(stderr, "dummy audit handler registration failed\n");
                _exit(1);
            }
        }
        execv(argv[1], &argv[1]);
        perror("execv");
        _exit(1);
    }
    int status;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status))
        return 1;
    return WEXITSTATUS(status);
}
