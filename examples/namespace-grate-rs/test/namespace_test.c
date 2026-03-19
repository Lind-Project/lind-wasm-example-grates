/* namespace_test.c — Test binary for the namespace clamping grate.
 *
 * Tests that path-prefix routing works correctly by exercising:
 *   1. Opens under the clamped prefix (should route to clamped grate)
 *   2. Opens outside the prefix (should passthrough to kernel)
 *   3. Read/write on clamped fds (should route based on fd origin)
 *   4. Read/write on non-clamped fds (should passthrough)
 *   5. Close on both types
 *   6. Dup of a clamped fd (new fd should also be clamped)
 *   7. Stat/access/mkdir/unlink on clamped and non-clamped paths
 *
 * Expected invocation:
 *   lind-wasm namespace-grate.cwasm --prefix /tmp %{ imfs-grate.cwasm %} namespace_test.cwasm
 *
 * The test prints PASS/FAIL for each case. The namespace grate should route
 * /tmp/* operations through IMFS and let everything else hit the kernel.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>

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

/* ── Test 1: Path-based routing (open) ─────────────────────────────────── */

static void test_open_routing(void) {
    printf("\n[test_open_routing]\n");

    /* Clamped path — should go through IMFS */
    int fd_tmp = open("/tmp/ns_test_file", O_CREAT | O_RDWR, 0644);
    CHECK("open /tmp/ns_test_file succeeds", fd_tmp >= 0);

    /* Non-clamped path — should go to kernel */
    int fd_dev = open("/dev/null", O_RDWR);
    CHECK("open /dev/null succeeds", fd_dev >= 0);

    if (fd_tmp >= 0) close(fd_tmp);
    if (fd_dev >= 0) close(fd_dev);
}

/* ── Test 2: FD-based routing (read/write) ─────────────────────────────── */

static void test_fd_routing(void) {
    printf("\n[test_fd_routing]\n");

    const char *msg = "hello from namespace test";
    char buf[64] = {0};

    /* Write to a clamped fd — should route through IMFS */
    int fd_tmp = open("/tmp/ns_test_rw", O_CREAT | O_RDWR | O_TRUNC, 0644);
    CHECK("open /tmp/ns_test_rw for write", fd_tmp >= 0);

    if (fd_tmp >= 0) {
        ssize_t nw = write(fd_tmp, msg, strlen(msg));
        CHECK("write to clamped fd succeeds", nw == (ssize_t)strlen(msg));

        /* Seek back and read */
        lseek(fd_tmp, 0, SEEK_SET);
        ssize_t nr = read(fd_tmp, buf, sizeof(buf) - 1);
        CHECK("read from clamped fd succeeds", nr == (ssize_t)strlen(msg));
        CHECK("read data matches written data", memcmp(buf, msg, strlen(msg)) == 0);

        close(fd_tmp);
    }

    /* Write to a non-clamped fd — should passthrough to kernel */
    int fd_dev = open("/dev/null", O_WRONLY);
    if (fd_dev >= 0) {
        ssize_t nw = write(fd_dev, msg, strlen(msg));
        CHECK("write to non-clamped fd succeeds", nw == (ssize_t)strlen(msg));
        close(fd_dev);
    }
}

/* ── Test 3: Dup preserves clamped status ──────────────────────────────── */

static void test_dup_routing(void) {
    printf("\n[test_dup_routing]\n");

    const char *msg = "dup test data";
    char buf[64] = {0};

    int fd_tmp = open("/tmp/ns_test_dup", O_CREAT | O_RDWR | O_TRUNC, 0644);
    CHECK("open /tmp/ns_test_dup", fd_tmp >= 0);

    if (fd_tmp >= 0) {
        int fd_dup = dup(fd_tmp);
        CHECK("dup of clamped fd succeeds", fd_dup >= 0);

        if (fd_dup >= 0) {
            /* Write through the dup'd fd — should still route to IMFS */
            ssize_t nw = write(fd_dup, msg, strlen(msg));
            CHECK("write through dup'd clamped fd", nw == (ssize_t)strlen(msg));

            /* Read back through original fd */
            lseek(fd_tmp, 0, SEEK_SET);
            ssize_t nr = read(fd_tmp, buf, sizeof(buf) - 1);
            CHECK("read back through original fd", nr == (ssize_t)strlen(msg));
            CHECK("data matches after dup write", memcmp(buf, msg, strlen(msg)) == 0);

            close(fd_dup);
        }
        close(fd_tmp);
    }
}

/* ── Test 4: Path-based syscalls (stat, access, mkdir, unlink) ─────────── */

static void test_path_syscalls(void) {
    printf("\n[test_path_syscalls]\n");

    /* mkdir under clamped prefix */
    int ret = mkdir("/tmp/ns_test_dir", 0755);
    CHECK("mkdir /tmp/ns_test_dir", ret == 0 || errno == EEXIST);

    /* stat under clamped prefix */
    struct stat st;
    ret = stat("/tmp/ns_test_dir", &st);
    CHECK("stat /tmp/ns_test_dir", ret == 0);

    /* access under clamped prefix */
    ret = access("/tmp/ns_test_dir", F_OK);
    CHECK("access /tmp/ns_test_dir", ret == 0);

    /* Create and unlink a file under clamped prefix */
    int fd = open("/tmp/ns_test_unlink", O_CREAT | O_WRONLY, 0644);
    if (fd >= 0) close(fd);
    ret = unlink("/tmp/ns_test_unlink");
    CHECK("unlink /tmp/ns_test_unlink", ret == 0);

    /* rmdir under clamped prefix */
    ret = rmdir("/tmp/ns_test_dir");
    CHECK("rmdir /tmp/ns_test_dir", ret == 0);

    /* stat on non-clamped path — should go to kernel */
    ret = stat("/dev/null", &st);
    CHECK("stat /dev/null (non-clamped, kernel)", ret == 0);
}

/* ── Test 5: Non-clamped fd isolation ──────────────────────────────────── */

static void test_isolation(void) {
    printf("\n[test_isolation]\n");

    /* Open a non-clamped path, write to it. This should never touch IMFS. */
    int fd = open("/dev/null", O_WRONLY);
    CHECK("open /dev/null for isolation test", fd >= 0);

    if (fd >= 0) {
        ssize_t nw = write(fd, "x", 1);
        CHECK("write to non-clamped fd goes to kernel", nw == 1);
        close(fd);
    }

    /* Verify a clamped path that doesn't exist fails with ENOENT */
    int fd2 = open("/tmp/ns_nonexistent_12345", O_RDONLY);
    CHECK("open nonexistent clamped path returns error", fd2 < 0);
}

/* ── Main ──────────────────────────────────────────────────────────────── */

int main(void) {
    printf("=== namespace grate test ===\n");

    test_open_routing();
    test_fd_routing();
    test_dup_routing();
    test_path_syscalls();
    test_isolation();

    printf("\n=== results: %d/%d passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
