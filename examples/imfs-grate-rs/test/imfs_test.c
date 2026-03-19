/* imfs_test.c — Test binary for the Rust IMFS grate.
 *
 * This is a cage binary that exercises the IMFS through standard POSIX syscalls.
 * The IMFS grate intercepts these syscalls and handles them in-memory.
 *
 * Expected invocation:
 *   lind-wasm imfs-grate-rs.cwasm imfs_test.cwasm
 *
 * Each test prints PASS/FAIL. Exit code 0 if all tests pass, 1 otherwise.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
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

/* ── Test 1: Basic open/write/read/close cycle ────────────────────────── */

static void test_basic_rw(void) {
    printf("\n[test_basic_rw]\n");

    const char *msg = "hello imfs";
    char buf[64] = {0};

    /* Create a new file and write to it. */
    int fd = open("/test_basic", O_CREAT | O_RDWR, 0644);
    CHECK("open /test_basic with O_CREAT", fd >= 0);
    if (fd < 0) return;

    ssize_t nw = write(fd, msg, strlen(msg));
    CHECK("write returns correct count", nw == (ssize_t)strlen(msg));

    /* Seek back to beginning and read. */
    off_t pos = lseek(fd, 0, SEEK_SET);
    CHECK("lseek to beginning returns 0", pos == 0);

    ssize_t nr = read(fd, buf, sizeof(buf) - 1);
    CHECK("read returns correct count", nr == (ssize_t)strlen(msg));
    CHECK("read data matches written data", memcmp(buf, msg, strlen(msg)) == 0);

    int ret = close(fd);
    CHECK("close succeeds", ret == 0);
}

/* ── Test 2: Open nonexistent file without O_CREAT ────────────────────── */

static void test_open_nocreat(void) {
    printf("\n[test_open_nocreat]\n");

    int fd = open("/does_not_exist", O_RDONLY);
    CHECK("open nonexistent without O_CREAT fails", fd < 0);
}

/* ── Test 3: O_APPEND writes at end ───────────────────────────────────── */

static void test_append(void) {
    printf("\n[test_append]\n");

    int fd = open("/test_append", O_CREAT | O_RDWR, 0644);
    CHECK("create /test_append", fd >= 0);
    if (fd < 0) return;

    write(fd, "aaa", 3);
    close(fd);

    /* Reopen with O_APPEND and write more. */
    fd = open("/test_append", O_WRONLY | O_APPEND);
    CHECK("reopen with O_APPEND", fd >= 0);
    if (fd < 0) return;

    write(fd, "bbb", 3);
    close(fd);

    /* Read back full contents. */
    fd = open("/test_append", O_RDONLY);
    CHECK("reopen for read", fd >= 0);
    if (fd < 0) return;

    char buf[64] = {0};
    ssize_t nr = read(fd, buf, sizeof(buf) - 1);
    CHECK("total size is 6", nr == 6);
    CHECK("data is aaabbb", memcmp(buf, "aaabbb", 6) == 0);

    close(fd);
}

/* ── Test 4: lseek with SEEK_CUR and SEEK_END ─────────────────────────── */

static void test_lseek(void) {
    printf("\n[test_lseek]\n");

    int fd = open("/test_lseek", O_CREAT | O_RDWR, 0644);
    CHECK("create /test_lseek", fd >= 0);
    if (fd < 0) return;

    write(fd, "0123456789", 10);

    /* SEEK_SET to position 5. */
    off_t pos = lseek(fd, 5, SEEK_SET);
    CHECK("SEEK_SET to 5", pos == 5);

    /* SEEK_CUR +2 = 7. */
    pos = lseek(fd, 2, SEEK_CUR);
    CHECK("SEEK_CUR +2 = 7", pos == 7);

    /* SEEK_END -3 = 7. */
    pos = lseek(fd, -3, SEEK_END);
    CHECK("SEEK_END -3 = 7", pos == 7);

    /* Read from position 7: should get "789". */
    char buf[4] = {0};
    ssize_t nr = read(fd, buf, 3);
    CHECK("read 3 bytes from pos 7", nr == 3);
    CHECK("data is 789", memcmp(buf, "789", 3) == 0);

    close(fd);
}

/* ── Test 5: pread and pwrite (positional, no offset change) ──────────── */

static void test_pread_pwrite(void) {
    printf("\n[test_pread_pwrite]\n");

    int fd = open("/test_preadwrite", O_CREAT | O_RDWR, 0644);
    CHECK("create /test_preadwrite", fd >= 0);
    if (fd < 0) return;

    write(fd, "AAAAAAAAAA", 10); /* 10 A's */

    /* pwrite "BB" at offset 3 — fd offset should NOT change. */
    ssize_t nw = pwrite(fd, "BB", 2, 3);
    CHECK("pwrite 2 bytes at offset 3", nw == 2);

    /* fd offset should still be 10 (from the initial write). */
    off_t pos = lseek(fd, 0, SEEK_CUR);
    CHECK("fd offset unchanged after pwrite", pos == 10);

    /* pread 4 bytes from offset 2. */
    char buf[5] = {0};
    ssize_t nr = pread(fd, buf, 4, 2);
    CHECK("pread 4 bytes from offset 2", nr == 4);
    CHECK("data is ABBA", memcmp(buf, "ABBA", 4) == 0);

    /* fd offset still unchanged. */
    pos = lseek(fd, 0, SEEK_CUR);
    CHECK("fd offset unchanged after pread", pos == 10);

    close(fd);
}

/* ── Test 6: mkdir and nested file creation ────────────────────────────── */

static void test_mkdir(void) {
    printf("\n[test_mkdir]\n");

    int ret = mkdir("/mydir", 0755);
    CHECK("mkdir /mydir", ret == 0);

    /* Create a file inside the directory. */
    int fd = open("/mydir/file.txt", O_CREAT | O_WRONLY, 0644);
    CHECK("create /mydir/file.txt", fd >= 0);
    if (fd >= 0) {
        write(fd, "nested", 6);
        close(fd);
    }

    /* Read it back. */
    fd = open("/mydir/file.txt", O_RDONLY);
    CHECK("reopen /mydir/file.txt", fd >= 0);
    if (fd >= 0) {
        char buf[16] = {0};
        ssize_t nr = read(fd, buf, sizeof(buf) - 1);
        CHECK("read nested file", nr == 6);
        CHECK("data is 'nested'", memcmp(buf, "nested", 6) == 0);
        close(fd);
    }

    /* mkdir on existing path should fail. */
    ret = mkdir("/mydir", 0755);
    CHECK("mkdir on existing dir fails", ret != 0);
}

/* ── Test 7: unlink ───────────────────────────────────────────────────── */

static void test_unlink(void) {
    printf("\n[test_unlink]\n");

    int fd = open("/test_unlink", O_CREAT | O_WRONLY, 0644);
    CHECK("create /test_unlink", fd >= 0);
    if (fd >= 0) {
        write(fd, "data", 4);
        close(fd);
    }

    int ret = unlink("/test_unlink");
    CHECK("unlink /test_unlink", ret == 0);

    /* Opening the unlinked file should fail. */
    fd = open("/test_unlink", O_RDONLY);
    CHECK("open after unlink fails", fd < 0);

    /* Unlink nonexistent should fail. */
    ret = unlink("/nonexistent");
    CHECK("unlink nonexistent fails", ret != 0);
}

/* ── Test 8: fcntl F_GETFL ────────────────────────────────────────────── */

static void test_fcntl(void) {
    printf("\n[test_fcntl]\n");

    int fd = open("/test_fcntl", O_CREAT | O_RDWR, 0644);
    CHECK("create /test_fcntl", fd >= 0);
    if (fd < 0) return;

    int flags = fcntl(fd, F_GETFL);
    CHECK("fcntl F_GETFL returns O_RDWR", (flags & O_ACCMODE) == O_RDWR);

    close(fd);
}

/* ── Test 9: Large write spanning multiple chunks ─────────────────────── */

static void test_large_write(void) {
    printf("\n[test_large_write]\n");

    /* Write 3000 bytes — should span 3 chunks (1024 each). */
    char wbuf[3000];
    for (int i = 0; i < 3000; i++) {
        wbuf[i] = 'A' + (i % 26);
    }

    int fd = open("/test_large", O_CREAT | O_RDWR, 0644);
    CHECK("create /test_large", fd >= 0);
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

/* ── Test 10: Read at EOF returns 0 ───────────────────────────────────── */

static void test_read_eof(void) {
    printf("\n[test_read_eof]\n");

    int fd = open("/test_eof", O_CREAT | O_RDWR, 0644);
    CHECK("create /test_eof", fd >= 0);
    if (fd < 0) return;

    write(fd, "hi", 2);

    /* Seek past end. */
    lseek(fd, 100, SEEK_SET);

    char buf[16];
    ssize_t nr = read(fd, buf, sizeof(buf));
    CHECK("read past EOF returns 0", nr == 0);

    close(fd);
}

/* ── Test 11: Write to stdout passes through (fd < 3) ─────────────────── */

static void test_stdout_passthrough(void) {
    printf("\n[test_stdout_passthrough]\n");

    /* This write should go to real stdout, not IMFS.
     * If it prints, the passthrough works. */
    const char *msg = "  PASS: stdout passthrough works\n";
    ssize_t nw = write(1, msg, strlen(msg));
    tests_run++;
    if (nw > 0) tests_passed++;
}

/* ── Main ──────────────────────────────────────────────────────────────── */

int main(void) {
    printf("=== imfs grate test ===\n");

    test_basic_rw();
    test_open_nocreat();
    test_append();
    test_lseek();
    test_pread_pwrite();
    test_mkdir();
    test_unlink();
    test_fcntl();
    test_large_write();
    test_read_eof();
    test_stdout_passthrough();

    printf("\n=== results: %d/%d passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
