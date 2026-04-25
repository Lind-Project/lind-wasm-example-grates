/*
 * Basic fs-view-grate test.
 *
 * Verifies that each cage gets its own filesystem view via path prefixing.
 * Uses the host filesystem (no imfs). Parent and child both write to /tmp/foo
 * and each should see their own file at /cage-<id>/tmp/foo on the host.
 *
 * Usage: lind-wasm grates/fs-view-grate.cwasm fs_view_test.cwasm
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

int main(void) {
    printf("=== fs-view-grate test ===\n");

    /* Create /tmp in our cage view */
    mkdir("/tmp", 0755);

    /* Parent writes to /tmp/foo */
    printf("\n[parent]\n");
    int fd = open("/tmp/foo.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
    CHECK("parent: create /tmp/foo.txt", fd >= 0);
    if (fd >= 0) {
        write(fd, "parent", 6);
        close(fd);
    }

    /* Fork child */
    pid_t pid = fork();
    if (pid == 0) {
        printf("\n[child]\n");

        /* Child creates its own /tmp */
        mkdir("/tmp", 0755);

        /* Child writes to /tmp/foo — should be independent */
        int cfd = open("/tmp/foo.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
        if (cfd < 0) {
            printf("  FAIL: child open (errno=%d)\n", errno);
            _exit(1);
        }
        write(cfd, "child", 5);
        close(cfd);

        /* Child reads back — should see "child" not "parent" */
        cfd = open("/tmp/foo.txt", O_RDONLY);
        if (cfd < 0) _exit(1);
        char buf[32] = {0};
        ssize_t n = read(cfd, buf, sizeof(buf) - 1);
        close(cfd);

        if (n == 5 && memcmp(buf, "child", 5) == 0) {
            printf("  PASS: child sees own data\n");
        } else {
            printf("  FAIL: child sees '%s' (expected 'child')\n", buf);
            _exit(1);
        }

        _exit(0);
    }

    int status;
    waitpid(pid, &status, 0);
    CHECK("child exited cleanly", WIFEXITED(status) && WEXITSTATUS(status) == 0);

    /* Parent reads back — should still see "parent" */
    fd = open("/tmp/foo.txt", O_RDONLY);
    CHECK("parent: reopen /tmp/foo.txt", fd >= 0);
    if (fd >= 0) {
        char buf[32] = {0};
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        CHECK("parent: still sees 'parent'", n == 6 && memcmp(buf, "parent", 6) == 0);
    }

    /* Cleanup */
    unlink("/tmp/foo.txt");

    printf("\n=== Result: %d/%d passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
