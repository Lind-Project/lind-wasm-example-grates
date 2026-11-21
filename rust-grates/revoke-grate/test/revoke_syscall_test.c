/*
 * Run as: revoke-grate revoke_syscall_test.cwasm
 *
 * Everything is revoked at runtime through the revoke syscall, both on this
 * cage and on a forked child. The revoked fds are regular files holding
 * "original", so a call that leaks through to the real file is visible.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../include/lind_revoke.h"

static int total = 0;
static int failures = 0;

#define CHECK(name, expr) do { \
    total++; \
    if (expr) { printf("PASS: %s\n", name); } \
    else { printf("FAIL: %s (errno=%d)\n", name, errno); failures++; } \
} while (0)

static const char *PATH = "/tmp/revoke_syscall_real.txt";
static int self;

static int all_zero(const char *p, size_t n) {
    for (size_t i = 0; i < n; i++) if (p[i]) return 0;
    return 1;
}

/* Read the whole file through a fresh descriptor. */
static int file_is(const char *want) {
    char buf[64] = {0};
    int fd = open(PATH, O_RDONLY);
    if (fd < 0) return 0;
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    return n == (ssize_t)strlen(want) && memcmp(buf, want, n) == 0;
}

/* Does `fd` read back the real file contents from the start? */
static int reads_original(int fd) {
    char buf[16] = {0};
    return lseek(fd, 0, SEEK_SET) == 0 && read(fd, buf, 8) == 8 &&
           memcmp(buf, "original", 8) == 0;
}

static void test_errors(void) {
    int fd = open(PATH, O_RDONLY);
    CHECK("open file", fd >= 0);

    errno = 0;
    CHECK("bad mode -> EINVAL", lind_revoke(self, fd, 7) == -1 && errno == EINVAL);
    errno = 0;
    CHECK("reserved flag bit -> EINVAL",
          lind_revoke(self, fd, 1 << 8) == -1 && errno == EINVAL);
    errno = 0;
    CHECK("fd not open -> EBADF", lind_revoke(self, 99, REVOKE_MODE_NULL) == -1 && errno == EBADF);
    errno = 0;
    CHECK("negative fd -> EBADF", lind_revoke(self, -1, REVOKE_MODE_NULL) == -1 && errno == EBADF);
    errno = 0;
    CHECK("unknown cage -> ESRCH", lind_revoke(9999, 0, REVOKE_MODE_NULL) == -1 && errno == ESRCH);
    CHECK("failed revokes left fd alone", reads_original(fd));
    close(fd);
}

static void test_null(void) {
    char buf[64];
    struct stat st;
    int fd = open(PATH, O_RDWR);
    CHECK("null: open file", fd >= 0);
    int keep = dup(fd); /* duplicated before the revoke: stays live (slot semantics) */

    CHECK("null: revoke own fd", lind_revoke(self, fd, REVOKE_MODE_NULL) == 0);

    /* reads hit EOF, buffer untouched */
    memset(buf, 0xAA, sizeof(buf));
    CHECK("null: read returns 0", read(fd, buf, sizeof(buf)) == 0);
    CHECK("null: read leaves buffer untouched", (unsigned char)buf[0] == 0xAA);
    struct iovec iov[1] = { { buf, sizeof(buf) } };
    CHECK("null: readv returns 0", readv(fd, iov, 1) == 0);

    /* writes are swallowed */
    CHECK("null: write returns count", write(fd, "CLOBBER", 7) == 7);
    struct iovec wv[2] = { { "ab", 2 }, { "cde", 3 } };
    CHECK("null: writev returns total", writev(fd, wv, 2) == 5);
    CHECK("null: file unchanged by swallowed writes", file_is("original"));

    /* not a tty, no metadata, not mappable */
    CHECK("null: isatty is 0", isatty(fd) == 0);
    errno = 0;
    CHECK("null: fstat -> EACCES", fstat(fd, &st) == -1 && errno == EACCES);
    errno = 0;
    void *m = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
    CHECK("null: mmap -> ENODEV", m == MAP_FAILED && errno == ENODEV);

    /* fcntl(F_DUPFD) carries the revocation */
    int d = fcntl(fd, F_DUPFD, 20);
    CHECK("null: F_DUPFD", d >= 20);
    CHECK("null: F_DUPFD'd fd reads EOF", read(d, buf, sizeof(buf)) == 0);
    close(d);

    /* other descriptors of the same file are untouched */
    CHECK("null: earlier dup is still live", reads_original(keep));
    CHECK("null: fstat on earlier dup works", fstat(keep, &st) == 0 && st.st_size == 8);

    CHECK("null: revoking again is fine", lind_revoke(self, fd, REVOKE_MODE_NULL) == 0);
    CHECK("null: close revoked fd", close(fd) == 0);
    close(keep);
}

static void test_zero(void) {
    char buf[64];
    struct stat st;
    int real = open(PATH, O_RDONLY);
    int fd = open(PATH, O_RDWR);
    CHECK("zero: open file", real >= 0 && fd >= 0);

    CHECK("zero: revoke own fd", lind_revoke(self, fd, REVOKE_MODE_ZERO) == 0);

    /* read returns zeros without overrunning */
    memset(buf, 0xAA, sizeof(buf));
    CHECK("zero: read returns count", read(fd, buf, 32) == 32);
    CHECK("zero: read fills zeros", all_zero(buf, 32));
    CHECK("zero: read does not overrun", (unsigned char)buf[32] == 0xAA);

    /* readv returns zeros across iovecs */
    char a[8], b[16];
    memset(a, 1, sizeof(a));
    memset(b, 1, sizeof(b));
    struct iovec iov[2] = { { a, sizeof(a) }, { b, sizeof(b) } };
    CHECK("zero: readv returns total", readv(fd, iov, 2) == 24);
    CHECK("zero: readv fills zeros", all_zero(a, sizeof(a)) && all_zero(b, sizeof(b)));

    /* writes are swallowed, lseek is a no-op, no metadata */
    CHECK("zero: write returns count", write(fd, "CLOBBER", 7) == 7);
    CHECK("zero: file unchanged by swallowed write", file_is("original"));
    CHECK("zero: lseek returns 0", lseek(fd, 100, SEEK_SET) == 0);
    errno = 0;
    CHECK("zero: fstat -> EACCES", fstat(fd, &st) == -1 && errno == EACCES);

    /* mmap gives zero pages */
    char *m = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    CHECK("zero: mmap succeeds", m != MAP_FAILED);
    if (m != MAP_FAILED) {
        CHECK("zero: mmap is zeroed", all_zero(m, 4096));
        munmap(m, 4096);
    }

    /* dup carries the revocation */
    int d = dup(fd);
    CHECK("zero: dup", d >= 0);
    memset(buf, 0xAA, sizeof(buf));
    CHECK("zero: dup'd fd reads zeros", read(d, buf, 16) == 16 && all_zero(buf, 16));
    CHECK("zero: close dup'd fd", close(d) == 0);

    /* dup2 carries it too, and overwriting the slot clears it */
    CHECK("zero: dup2 -> 10", dup2(fd, 10) == 10);
    memset(buf, 0xAA, sizeof(buf));
    CHECK("zero: fd 10 reads zeros", read(10, buf, 4) == 4 && all_zero(buf, 4));
    CHECK("zero: dup2 real fd -> 10", dup2(real, 10) == 10);
    CHECK("zero: fd 10 now reads the file", reads_original(10));
    close(10);

    /* forked child inherits the revocation */
    pid_t pid = fork();
    if (pid == 0) {
        char cbuf[16];
        memset(cbuf, 0xAA, sizeof(cbuf));
        _exit(read(fd, cbuf, 16) == 16 && all_zero(cbuf, 16) ? 0 : 1);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    CHECK("zero: forked child inherits revocation",
          WIFEXITED(status) && WEXITSTATUS(status) == 0);

    /* closing the revoked fd clears the slot for whatever reuses the number */
    CHECK("zero: close revoked fd", close(fd) == 0);
    int again = open(PATH, O_RDONLY);
    CHECK("zero: reopen reuses the fd number", again == fd);
    CHECK("zero: reused fd reads the file", reads_original(again));
    close(again);
    close(real);
}

static void test_revoke_child(void) {
    pid_t child;
    int fd = open(PATH, O_RDONLY);
    int go[2];
    CHECK("child: pipe", fd >= 0 && pipe(go) == 0);

    child = fork();
    if (child == 0) {
        char c, cbuf[16];
        close(go[1]);
        if (read(go[0], &c, 1) != 1) _exit(2); /* wait for the parent's revoke */
        memset(cbuf, 0xAA, sizeof(cbuf));
        _exit(read(fd, cbuf, sizeof(cbuf)) == 0 ? 0 : 1);
    }
    close(go[0]);
    CHECK("child: revoke child's fd", lind_revoke(child, fd, REVOKE_MODE_NULL) == 0);
    write(go[1], "g", 1);
    int status = 0;
    waitpid(child, &status, 0);
    CHECK("child: sees its fd revoked", WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK("child: parent's copy is unaffected", reads_original(fd));
    close(fd);
    close(go[1]);

    errno = 0;
    CHECK("child: exited child -> ESRCH",
          lind_revoke(child, 0, REVOKE_MODE_NULL) == -1 && errno == ESRCH);
}

int main(void) {
    self = getpid();

    int fd = open(PATH, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    CHECK("create file", fd >= 0 && write(fd, "original", 8) == 8);
    close(fd);

    test_errors();
    test_null();
    test_zero();
    test_revoke_child();

    unlink(PATH);
    printf("\nResult: %d/%d passed\n", total - failures, total);
    return failures ? 1 : 0;
}
