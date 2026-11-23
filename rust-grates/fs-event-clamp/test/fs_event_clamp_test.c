#include <errno.h>
#include <fcntl.h>
#include <lind_syscall.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

// Readable, non-matching file opened before activation. lindfs has no /dev/zero.
#define DATA_PATH "/tmp/fs_event_clamp_data"

// Lind's glibc does not implement syscall(); dispatch through the cage's own handler table.
static long custom_syscall(unsigned int nr) {
    uint64_t self = getpid();
    return make_threei_call(nr, 0, self, self, 0, self, 0, self, 0, self, 0, self, 0, self, 0, self, 0);
}

static int audited(void) {
    char byte = 0;
    errno = 0;
    if (geteuid() != 166)
        return 1;
    if (read(STDIN_FILENO, &byte, 1) != -1 || errno != 166)
        return 2;
    errno = 0;
    if (write(STDOUT_FILENO, &byte, 1) != -1 || errno != 167)
        return 3;
    return 0;
}

static int wait_success(pid_t child) {
    int status;
    return child > 0 && waitpid(child, &status, 0) == child &&
           WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static int run_case(int use_openat, const char *program, int dummy_audit) {
    char byte;
    int oldfd = open(DATA_PATH, O_RDWR);
    if (oldfd < 0 || read(oldfd, &byte, 1) != 1 || geteuid() == 166)
        return 10;

    struct stat st;
    if (stat("/dev/null", &st) != 0 || geteuid() == 166)
        return 11;
    if (open("/dev/not-a-real-secret", O_RDONLY) != -1 || geteuid() == 166)
        return 12;

    int dirfd = open("/dev", O_RDONLY | O_DIRECTORY);
    if (dirfd < 0)
        return 13;
    int secret = use_openat ? openat(dirfd, "null", O_RDONLY)
                            : open("/dev/null", O_RDONLY);
    if (secret < 0 || audited() != 0)
        return 14;

    if (dummy_audit) {
        if (custom_syscall(2048) != 168 || custom_syscall(2049) != 169)
            return 21;
        errno = 0;
        if (open(DATA_PATH, O_RDONLY) != -1 || errno != 168)
            return 22;
    }

    errno = 0;
    if (read(oldfd, &byte, 1) != -1 || errno != 166)
        return 15;
    errno = 0;
    if (write(oldfd, &byte, 1) != -1 || errno != 167)
        return 16;
    if (close(secret) != 0 || audited() != 0)
        return 17;

    pid_t child = fork();
    if (child == 0)
        _exit(audited());
    if (!wait_success(child))
        return 18;

    child = fork();
    if (child == 0) {
        execl(program, program, "--audited-child", (char *)NULL);
        _exit(19);
    }
    if (!wait_success(child))
        return 20;
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--audited-child") == 0)
        return audited();

    int dummy_audit = argc == 2 && strcmp(argv[1], "--dummy-audit") == 0;
    int data = open(DATA_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (data < 0 || write(data, "x", 1) != 1 || close(data) != 0) {
        perror(DATA_PATH);
        return 1;
    }
    for (int use_openat = 0; use_openat <= 1; use_openat++) {
        pid_t child = fork();
        if (child == 0)
            _exit(run_case(use_openat, argv[0], dummy_audit));
        if (!wait_success(child)) {
            fprintf(stderr, "fs-event-clamp case %d failed\n", use_openat);
            return 1;
        }
        if (geteuid() == 166) {
            fprintf(stderr, "activation leaked into the parent cage\n");
            return 1;
        }
    }
    puts("fs-event-clamp tests passed");
    return 0;
}
