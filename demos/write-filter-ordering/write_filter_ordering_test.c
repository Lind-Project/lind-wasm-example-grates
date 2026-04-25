/*
 * Write filter + strace composition ordering demo.
 *
 * The test program attempts writes to both allowed (.log) and denied
 * (.db) files. The composition order of strace-grate and write-filter-grate
 * determines what appears in the trace.
 *
 * Ordering A (strace above write-filter):
 *   strace sees ALL attempted writes, including denied ones.
 *
 * Ordering B (write-filter above strace):
 *   strace sees ONLY permitted writes. Denied writes never reach strace.
 *
 * This test verifies:
 * 1. write to output.log succeeds (allowed by write-filter)
 * 2. write to data.db fails with EPERM (denied by write-filter)
 * 3. pwrite to data.db also fails with EPERM
 * 4. write to another.log succeeds
 *
 * Run this under both orderings and compare the strace output.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int tests_run = 0;
static int tests_passed = 0;

#define CHECK(name, expr) do { \
    tests_run++; \
    if (expr) { printf("  PASS: %s\n", name); tests_passed++; } \
    else { printf("  FAIL: %s (errno=%d %s)\n", name, errno, strerror(errno)); } \
} while (0)

int main(void) {
    printf("=== Write Filter Ordering Demo ===\n\n");

    int fd;
    ssize_t ret;

    /* Test 1: write to .log file — should succeed */
    printf("[test_allowed_write]\n");
    fd = open("output.log", O_CREAT | O_WRONLY | O_TRUNC, 0644);
    CHECK("open output.log", fd >= 0);
    if (fd >= 0) {
        ret = write(fd, "log entry 1\n", 12);
        CHECK("write to output.log succeeds", ret == 12);
        close(fd);
    }

    /* Test 2: write to .db file — should be denied with EPERM */
    printf("\n[test_denied_write]\n");
    fd = open("data.db", O_CREAT | O_WRONLY | O_TRUNC, 0644);
    CHECK("open data.db", fd >= 0);
    if (fd >= 0) {
        errno = 0;
        ret = write(fd, "secret data\n", 12);
        CHECK("write to data.db denied (EPERM)", ret == -1 && errno == EPERM);
        close(fd);
    }

    /* Test 3: pwrite to .db file — also denied */
    printf("\n[test_denied_pwrite]\n");
    fd = open("data.db", O_CREAT | O_WRONLY | O_TRUNC, 0644);
    CHECK("open data.db for pwrite", fd >= 0);
    if (fd >= 0) {
        errno = 0;
        ret = pwrite(fd, "secret pwrite\n", 14, 0);
        CHECK("pwrite to data.db denied (EPERM)", ret == -1 && errno == EPERM);
        close(fd);
    }

    /* Test 4: write to another .log file — should succeed */
    printf("\n[test_another_allowed]\n");
    fd = open("another.log", O_CREAT | O_WRONLY | O_TRUNC, 0644);
    CHECK("open another.log", fd >= 0);
    if (fd >= 0) {
        ret = write(fd, "log entry 2\n", 12);
        CHECK("write to another.log succeeds", ret == 12);
        close(fd);
    }

    /* Test 5: read from .db file — should work (only writes are filtered) */
    printf("\n[test_read_not_filtered]\n");
    fd = open("data.db", O_RDONLY);
    if (fd >= 0) {
        char buf[64] = {0};
        ret = read(fd, buf, sizeof(buf));
        CHECK("read from data.db not blocked", ret >= 0);
        close(fd);
    }

    /* Cleanup */
    unlink("output.log");
    unlink("data.db");
    unlink("another.log");

    printf("\n=== Result: %d/%d passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
