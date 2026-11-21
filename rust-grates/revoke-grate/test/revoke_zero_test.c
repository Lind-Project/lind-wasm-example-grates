/*
 * Run as: revoke-grate --revoke 2:0:zero revoke_zero_test.cwasm
 *
 * The grate is cage 1, so this program is cage 2 and its stdin (fd 0) is
 * revoked as /dev/zero.
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

static int total = 0;
static int failures = 0;

#define CHECK(name, expr) do { \
    total++; \
    if (expr) { printf("PASS: %s\n", name); } \
    else { printf("FAIL: %s (errno=%d)\n", name, errno); failures++; } \
} while (0)

static int all_zero(const char *p, size_t n) {
    for (size_t i = 0; i < n; i++) if (p[i]) return 0;
    return 1;
}

static const char *REAL = "/tmp/revoke_zero_real.txt";

int main(void) {
    char buf[64];
    ssize_t ret;

    /* read returns zeros */
    memset(buf, 0xAA, sizeof(buf));
    ret = read(0, buf, 32);
    CHECK("read revoked fd returns count", ret == 32);
    CHECK("read revoked fd fills zeros", all_zero(buf, 32));
    CHECK("read does not overrun", (unsigned char)buf[32] == 0xAA);

    /* readv returns zeros across iovecs */
    char a[8], b[16];
    memset(a, 1, sizeof(a));
    memset(b, 1, sizeof(b));
    struct iovec iov[2] = { { a, sizeof(a) }, { b, sizeof(b) } };
    ret = readv(0, iov, 2);
    CHECK("readv revoked fd returns total", ret == 24);
    CHECK("readv fills zeros", all_zero(a, sizeof(a)) && all_zero(b, sizeof(b)));

    /* writes are swallowed */
    CHECK("write revoked fd returns count", write(0, "hello", 5) == 5);

    /* lseek returns 0 */
    CHECK("lseek revoked fd returns 0", lseek(0, 100, SEEK_SET) == 0);

    /* fstat does not leak the real object */
    struct stat st;
    errno = 0;
    CHECK("fstat revoked fd -> EACCES", fstat(0, &st) == -1 && errno == EACCES);

    /* dup carries the revocation */
    int d = dup(0);
    CHECK("dup revoked fd", d >= 0);
    memset(buf, 0xAA, sizeof(buf));
    CHECK("read dup'd fd returns zeros", read(d, buf, 16) == 16 && all_zero(buf, 16));
    CHECK("close dup'd fd", close(d) == 0);

    /* dup2 carries it too, and overwriting the slot clears it */
    int fd = open(REAL, O_CREAT | O_RDWR | O_TRUNC, 0644);
    CHECK("open real file", fd >= 0);
    CHECK("write real file", write(fd, "real data", 9) == 9);
    CHECK("dup2 revoked fd -> 10", dup2(0, 10) == 10);
    memset(buf, 0xAA, sizeof(buf));
    CHECK("read fd 10 returns zeros", read(10, buf, 4) == 4 && all_zero(buf, 4));
    CHECK("dup2 real fd -> 10", dup2(fd, 10) == 10);
    lseek(10, 0, SEEK_SET);
    memset(buf, 0, sizeof(buf));
    CHECK("fd 10 now reads real data",
          read(10, buf, sizeof(buf)) == 9 && memcmp(buf, "real data", 9) == 0);
    close(10);

    /* mmap of a revoked fd gives zero pages */
    char *m = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE, 0, 0);
    CHECK("mmap revoked fd succeeds", m != MAP_FAILED);
    if (m != MAP_FAILED) {
        CHECK("mmap revoked fd is zeroed", all_zero(m, 4096));
        munmap(m, 4096);
    }

    /* forked child inherits the revocation */
    pid_t pid = fork();
    if (pid == 0) {
        char cbuf[16];
        memset(cbuf, 0xAA, sizeof(cbuf));
        _exit(read(0, cbuf, 16) == 16 && all_zero(cbuf, 16) ? 0 : 1);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    CHECK("forked child sees revoked fd",
          WIFEXITED(status) && WEXITSTATUS(status) == 0);

    /* closing the revoked fd clears the revocation for the slot */
    CHECK("close revoked fd", close(0) == 0);
    int fd0 = open(REAL, O_RDONLY);
    CHECK("reopen lands on fd 0", fd0 == 0);
    memset(buf, 0, sizeof(buf));
    CHECK("fd 0 now reads real data",
          read(fd0, buf, sizeof(buf)) == 9 && memcmp(buf, "real data", 9) == 0);
    close(fd0);
    close(fd);
    unlink(REAL);

    printf("\nResult: %d/%d passed\n", total - failures, total);
    return failures ? 1 : 0;
}
