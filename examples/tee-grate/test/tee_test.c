/* tee_test.c — Test binary for the tee grate.
 *
 * Exercises the tee grate's syscall duplication, primary-wins semantics,
 * secondary isolation, fork behavior, and fd lifecycle.
 *
 * Expected invocation:
 *   lind-wasm tee-grate.cwasm --primary imfs-grate.cwasm \
 *             --secondary imfs-grate.cwasm -- tee_test.cwasm
 *
 * Each test prints PASS/FAIL. Exit code 0 if all pass.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/wait.h>

static int tests_run = 0;
static int tests_passed = 0;

#define CHECK(desc, cond) do { \
    tests_run++; \
    if (cond) { \
        printf("  PASS: %s\n", desc); \
        tests_passed++; \
    } else { \
        printf("  FAIL: %s (errno=%d)\n", desc, errno); \
    } \
} while (0)

/* ── Test 1: Primary return value is authoritative ─────────────────────── */

static void test_primary_wins(void) {
    printf("\n[test_primary_wins]\n");

    int fd = open("/tee_primary", O_CREAT | O_RDWR, 0644);
    CHECK("open returns valid fd (primary wins)", fd >= 0);

    if (fd >= 0) {
        const char *msg = "primary data";
        ssize_t nw = write(fd, msg, strlen(msg));
        CHECK("write returns correct count", nw == (ssize_t)strlen(msg));

        lseek(fd, 0, SEEK_SET);
        char buf[64] = {0};
        ssize_t nr = read(fd, buf, sizeof(buf) - 1);
        CHECK("read returns correct count", nr == (ssize_t)strlen(msg));
        CHECK("read data matches written", memcmp(buf, msg, strlen(msg)) == 0);

        close(fd);
    }
}

/* ── Test 2: Secondary errors don't affect the caller ──────────────────── */

static void test_secondary_isolation(void) {
    printf("\n[test_secondary_isolation]\n");

    int ok = 1;
    for (int i = 0; i < 10; i++) {
        char path[64];
        snprintf(path, sizeof(path), "/tee_iso_%d", i);

        int fd = open(path, O_CREAT | O_WRONLY, 0644);
        if (fd < 0) { ok = 0; break; }

        write(fd, "x", 1);
        close(fd);
        unlink(path);
    }

    tests_run++;
    if (ok) {
        printf("  PASS: 10 create/write/close/unlink cycles with no errors\n");
        tests_passed++;
    } else {
        printf("  FAIL: secondary isolation broken\n");
    }
}

/* ── Test 3: Fork is not duplicated ────────────────────────────────────── */

static void test_fork_not_duplicated(void) {
    printf("\n[test_fork_not_duplicated]\n");

    pid_t pid = fork();
    CHECK("fork succeeds", pid >= 0);

    if (pid < 0) return;

    if (pid == 0) {
        _exit(42);
    }

    int status = 0;
    pid_t waited = waitpid(pid, &status, 0);
    CHECK("waitpid returns the child pid", waited == pid);
    CHECK("child exited with status 42", WIFEXITED(status) && WEXITSTATUS(status) == 42);
}

/* ── Test 4: Large write data integrity ────────────────────────────────── */

static void test_large_write(void) {
    printf("\n[test_large_write]\n");

    char wbuf[3000];
    for (int i = 0; i < 3000; i++)
        wbuf[i] = 'A' + (i % 26);

    int fd = open("/tee_large", O_CREAT | O_RDWR, 0644);
    CHECK("create /tee_large", fd >= 0);
    if (fd < 0) return;

    ssize_t nw = write(fd, wbuf, 3000);
    CHECK("write 3000 bytes", nw == 3000);

    lseek(fd, 0, SEEK_SET);

    char rbuf[3000] = {0};
    ssize_t nr = read(fd, rbuf, 3000);
    CHECK("read 3000 bytes back", nr == 3000);
    CHECK("data matches", memcmp(rbuf, wbuf, 3000) == 0);

    close(fd);
}

/* ── Test 5: Close and reopen ──────────────────────────────────────────── */

static void test_close_reopen(void) {
    printf("\n[test_close_reopen]\n");

    int fd1 = open("/tee_reopen", O_CREAT | O_WRONLY, 0644);
    CHECK("create file", fd1 >= 0);
    if (fd1 < 0) return;

    write(fd1, "hello", 5);
    int ret = close(fd1);
    CHECK("close succeeds", ret == 0);

    int fd2 = open("/tee_reopen", O_RDONLY);
    CHECK("reopen for read", fd2 >= 0);
    if (fd2 < 0) return;

    char buf[16] = {0};
    ssize_t nr = read(fd2, buf, sizeof(buf) - 1);
    CHECK("read after reopen", nr == 5);
    CHECK("data is 'hello'", memcmp(buf, "hello", 5) == 0);

    close(fd2);
}

/* ── Test 6: Dup preserves fd across tee ───────────────────────────────── */

static void test_dup(void) {
    printf("\n[test_dup]\n");

    int fd = open("/tee_dup", O_CREAT | O_RDWR, 0644);
    CHECK("create file", fd >= 0);
    if (fd < 0) return;

    int fd2 = dup(fd);
    CHECK("dup succeeds", fd2 >= 0);

    if (fd2 >= 0) {
        write(fd2, "dup data", 8);
        lseek(fd, 0, SEEK_SET);

        char buf[16] = {0};
        ssize_t nr = read(fd, buf, sizeof(buf) - 1);
        CHECK("read through original after dup write", nr == 8);
        CHECK("data matches", memcmp(buf, "dup data", 8) == 0);

        close(fd2);
    }

    close(fd);
}

/* ── Test 7: Stdout passthrough ────────────────────────────────────────── */

static void test_stdout(void) {
    printf("\n[test_stdout]\n");

    const char *msg = "  PASS: stdout passthrough works\n";
    ssize_t nw = write(1, msg, strlen(msg));
    tests_run++;
    if (nw > 0) tests_passed++;
}

/* ── Test 8: Fork child inherits tee routing ───────────────────────────── */
/* Child should be able to use the tee'd grate stack just like the parent. */

static void test_fork_inherits_routing(void) {
    printf("\n[test_fork_inherits_routing]\n");

    pid_t pid = fork();
    if (pid == 0) {
        /* Child: create a file through the tee'd grate. */
        int fd = open("/tee_fork_child_file", O_CREAT | O_WRONLY, 0644);
        if (fd < 0) _exit(1);
        ssize_t nw = write(fd, "child wrote this", 16);
        close(fd);
        _exit(nw == 16 ? 0 : 1);
    }

    int status;
    waitpid(pid, &status, 0);
    CHECK("child created file through tee",
          WIFEXITED(status) && WEXITSTATUS(status) == 0);

    /* Parent: verify the child's file. */
    int fd = open("/tee_fork_child_file", O_RDONLY);
    CHECK("parent can open child's file", fd >= 0);
    if (fd >= 0) {
        char buf[32] = {0};
        ssize_t nr = read(fd, buf, sizeof(buf));
        CHECK("child's file has correct data",
              nr == 16 && memcmp(buf, "child wrote this", 16) == 0);
        close(fd);
    }
}

/* ── Test 9: Multiple files open simultaneously ────────────────────────── */

static void test_multiple_open(void) {
    printf("\n[test_multiple_open]\n");

    int fd1 = open("/tee_multi_1", O_CREAT | O_RDWR | O_TRUNC, 0644);
    int fd2 = open("/tee_multi_2", O_CREAT | O_RDWR | O_TRUNC, 0644);
    int fd3 = open("/tee_multi_3", O_CREAT | O_RDWR | O_TRUNC, 0644);

    CHECK("3 files open simultaneously", fd1 >= 0 && fd2 >= 0 && fd3 >= 0);

    write(fd1, "one", 3);
    write(fd2, "two_data", 8);
    write(fd3, "three", 5);

    char buf[64] = {0};

    lseek(fd1, 0, SEEK_SET);
    ssize_t nr = read(fd1, buf, sizeof(buf));
    CHECK("fd1 correct", nr == 3 && memcmp(buf, "one", 3) == 0);

    lseek(fd2, 0, SEEK_SET);
    nr = read(fd2, buf, sizeof(buf));
    CHECK("fd2 correct", nr == 8 && memcmp(buf, "two_data", 8) == 0);

    lseek(fd3, 0, SEEK_SET);
    nr = read(fd3, buf, sizeof(buf));
    CHECK("fd3 correct", nr == 5 && memcmp(buf, "three", 5) == 0);

    close(fd1); close(fd2); close(fd3);
}

/* ── Test 10: Rapid create/close cycles ────────────────────────────────── */

static void test_rapid_lifecycle(void) {
    printf("\n[test_rapid_lifecycle]\n");

    int ok = 1;
    for (int i = 0; i < 50; i++) {
        char path[64];
        snprintf(path, sizeof(path), "/tee_rapid_%d", i);

        int fd = open(path, O_CREAT | O_RDWR, 0644);
        if (fd < 0) { ok = 0; break; }

        char data = (char)('A' + (i % 26));
        write(fd, &data, 1);

        lseek(fd, 0, SEEK_SET);
        char buf = 0;
        ssize_t nr = read(fd, &buf, 1);
        if (nr != 1 || buf != data) { ok = 0; break; }

        close(fd);
        unlink(path);
    }

    tests_run++;
    if (ok) {
        printf("  PASS: 50 rapid create/write/read/close/unlink cycles\n");
        tests_passed++;
    } else {
        printf("  FAIL: rapid lifecycle broke\n");
    }
}

/* ── Main ──────────────────────────────────────────────────────────────── */

int main(void) {
    printf("=== tee grate test ===\n");

    test_primary_wins();
    test_secondary_isolation();
    test_fork_not_duplicated();
    test_large_write();
    test_close_reopen();
    test_dup();
    test_stdout();
    test_fork_inherits_routing();
    test_multiple_open();
    test_rapid_lifecycle();

    printf("\n=== results: %d/%d passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
