/*
 * Least-privilege confinement test.
 *
 * Verifies that filesystem access is confined to /workspace across
 * multiple spawn depths. Paths outside /workspace should return EPERM
 * (from seccomp-grate), while /workspace paths succeed (via imfs-grate
 * through fs-routing-clamp routing).
 *
 * Usage (composed):
 *   lind-wasm grates/seccomp-grate.cwasm seccomp_fs_deny.conf \
 *     grates/fs-routing-clamp.cwasm --prefix /workspace %{ \
 *       grates/imfs-grate.cwasm \
 *     %} least_privilege_test.cwasm
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static int tests_run = 0;
static int tests_passed = 0;

#define CHECK(name, expr) do { \
    tests_run++; \
    if (expr) { printf("  PASS: %s\n", name); tests_passed++; } \
    else { printf("  FAIL: %s (errno=%d %s)\n", name, errno, strerror(errno)); } \
} while (0)

/* Try to open a path. Returns the fd on success, -1 on failure. */
static int try_open(const char *path, int flags) {
    errno = 0;
    int fd = open(path, flags, 0644);
    return fd;
}

/* Run the confinement checks at the current spawn depth. */
static void run_checks(int depth) {
    char label[128];

    printf("\n[depth %d, pid %d]\n", depth, getpid());

    /* /workspace should be accessible (routed to imfs) */
    snprintf(label, sizeof(label), "depth %d: open /workspace/test.txt (O_CREAT)", depth);
    int fd = try_open("/workspace/test.txt", O_CREAT | O_RDWR);
    CHECK(label, fd >= 0);
    if (fd >= 0) {
        write(fd, "hello", 5);
        close(fd);
    }

    snprintf(label, sizeof(label), "depth %d: open /workspace/test.txt (O_RDONLY)", depth);
    fd = try_open("/workspace/test.txt", O_RDONLY);
    CHECK(label, fd >= 0);
    if (fd >= 0) {
        char buf[16] = {0};
        read(fd, buf, 5);
        snprintf(label, sizeof(label), "depth %d: read /workspace/test.txt", depth);
        CHECK(label, memcmp(buf, "hello", 5) == 0);
        close(fd);
    }

    /* Paths outside /workspace should be denied with EPERM */
    snprintf(label, sizeof(label), "depth %d: open /etc/passwd denied", depth);
    fd = try_open("/etc/passwd", O_RDONLY);
    CHECK(label, fd < 0 && errno == EPERM);
    if (fd >= 0) close(fd);

    snprintf(label, sizeof(label), "depth %d: open /home/user/file denied", depth);
    fd = try_open("/home/user/file", O_RDONLY);
    CHECK(label, fd < 0 && errno == EPERM);
    if (fd >= 0) close(fd);

    snprintf(label, sizeof(label), "depth %d: open /tmp/escape denied", depth);
    fd = try_open("/tmp/escape", O_CREAT | O_RDWR);
    CHECK(label, fd < 0 && errno == EPERM);
    if (fd >= 0) close(fd);

    snprintf(label, sizeof(label), "depth %d: mkdir /outside denied", depth);
    int ret = mkdir("/outside", 0755);
    CHECK(label, ret < 0 && errno == EPERM);

    /* Clean up */
    unlink("/workspace/test.txt");
}

int main(void) {
    printf("=== Least-Privilege Confinement Test ===\n");

    /* Create /workspace directory in imfs */
    mkdir("/workspace", 0755);

    /* Depth 0: parent process */
    run_checks(0);

    /* Depth 1: forked child */
    pid_t pid1 = fork();
    if (pid1 == 0) {
        run_checks(1);

        /* Depth 2: grandchild */
        pid_t pid2 = fork();
        if (pid2 == 0) {
            run_checks(2);
            _exit(0);
        }
        if (pid2 > 0) {
            int status;
            waitpid(pid2, &status, 0);
        }
        _exit(0);
    }

    if (pid1 > 0) {
        int status;
        waitpid(pid1, &status, 0);
    }

    printf("\n=== Result: %d/%d passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
