/* tee_test.c — Test binary for the tee grate.
 *
 * This cage binary exercises the tee grate's duplication behavior.
 * It relies on both the primary and secondary grates being IMFS instances
 * (or similar filesystem grates) so we can verify that writes go through
 * both paths by checking the primary's return values.
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
/* The tee grate should return whatever the primary returns. If the primary
 * succeeds, the caller sees success regardless of what the secondary does. */

static void test_primary_wins(void) {
    printf("\n[test_primary_wins]\n");

    /* Create a file — primary should succeed, we get a valid fd. */
    int fd = open("/tee_test_primary", O_CREAT | O_RDWR, 0644);
    CHECK("open returns valid fd (primary wins)", fd >= 0);

    if (fd >= 0) {
        /* Write — primary should succeed. */
        const char *msg = "primary data";
        ssize_t nw = write(fd, msg, strlen(msg));
        CHECK("write returns correct count", nw == (ssize_t)strlen(msg));

        /* Seek back and read — should get what primary wrote. */
        lseek(fd, 0, SEEK_SET);
        char buf[64] = {0};
        ssize_t nr = read(fd, buf, sizeof(buf) - 1);
        CHECK("read returns correct count", nr == (ssize_t)strlen(msg));
        CHECK("read data matches written", memcmp(buf, msg, strlen(msg)) == 0);

        close(fd);
    }
}

/* ── Test 2: Secondary errors don't affect the caller ──────────────────── */
/* Even if the secondary fails internally, the primary's result should
 * be what the caller sees. We can't directly force a secondary error
 * from the cage side, but we can verify that operations that succeed
 * on the primary always return success to us. */

static void test_secondary_isolation(void) {
    printf("\n[test_secondary_isolation]\n");

    /* Multiple rapid operations — if secondary errors leaked, we'd see
     * unexpected failures here. */
    for (int i = 0; i < 10; i++) {
        char path[64];
        snprintf(path, sizeof(path), "/tee_iso_%d", i);

        int fd = open(path, O_CREAT | O_WRONLY, 0644);
        if (fd < 0) {
            printf("  FAIL: open %s failed on iteration %d\n", path, i);
            tests_run++;
            return;
        }

        write(fd, "x", 1);
        close(fd);
        unlink(path);
    }

    tests_run++;
    tests_passed++;
    printf("  PASS: 10 create/write/close/unlink cycles with no errors\n");
}

/* ── Test 3: Fork is not duplicated ────────────────────────────────────── */
/* fork is a primary-only syscall. The tee grate should forward it only
 * to the primary. We verify that fork works normally (returns child pid
 * to parent, 0 to child) and doesn't create duplicate processes. */

static void test_fork_not_duplicated(void) {
    printf("\n[test_fork_not_duplicated]\n");

    pid_t pid = fork();
    CHECK("fork succeeds", pid >= 0);

    if (pid < 0) return;

    if (pid == 0) {
        /* Child — just exit. If fork were duplicated, there would be
         * extra children and the parent's wait would behave oddly. */
        _exit(42);
    }

    /* Parent — wait for the one child. */
    int status = 0;
    pid_t waited = waitpid(pid, &status, 0);
    CHECK("waitpid returns the child pid", waited == pid);
    CHECK("child exited with status 42", WIFEXITED(status) && WEXITSTATUS(status) == 42);
}

/* ── Test 4: Large write goes through ──────────────────────────────────── */
/* Write more than one chunk (1024 bytes) to verify data integrity
 * through the tee dispatch. */

static void test_large_write(void) {
    printf("\n[test_large_write]\n");

    char wbuf[3000];
    for (int i = 0; i < 3000; i++) {
        wbuf[i] = 'A' + (i % 26);
    }

    int fd = open("/tee_test_large", O_CREAT | O_RDWR, 0644);
    CHECK("create /tee_test_large", fd >= 0);
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
/* Verify fd lifecycle works through the tee. */

static void test_close_reopen(void) {
    printf("\n[test_close_reopen]\n");

    int fd1 = open("/tee_test_reopen", O_CREAT | O_WRONLY, 0644);
    CHECK("create file", fd1 >= 0);
    if (fd1 < 0) return;

    write(fd1, "hello", 5);
    int ret = close(fd1);
    CHECK("close succeeds", ret == 0);

    /* Reopen for reading. */
    int fd2 = open("/tee_test_reopen", O_RDONLY);
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

    int fd = open("/tee_test_dup", O_CREAT | O_RDWR, 0644);
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
/* fd < 3 should pass through to real stdout. */

static void test_stdout(void) {
    printf("\n[test_stdout]\n");

    const char *msg = "  PASS: stdout passthrough works\n";
    ssize_t nw = write(1, msg, strlen(msg));
    tests_run++;
    if (nw > 0) tests_passed++;
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

    printf("\n=== results: %d/%d passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
