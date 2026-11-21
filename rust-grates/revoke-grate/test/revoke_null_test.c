/*
 * Run as: revoke-grate --revoke 2:0 revoke_null_test.cwasm
 *
 * The grate is cage 1, so this program is cage 2 and its stdin (fd 0) is
 * revoked as /dev/null.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>

static int total = 0;
static int failures = 0;

#define CHECK(name, expr) do { \
    total++; \
    if (expr) { printf("PASS: %s\n", name); } \
    else { printf("FAIL: %s (errno=%d)\n", name, errno); failures++; } \
} while (0)

static const char *REAL = "/tmp/revoke_null_real.txt";

int main(void) {
    char buf[64];

    /* reads hit EOF, buffer untouched */
    memset(buf, 0xAA, sizeof(buf));
    CHECK("read revoked fd returns 0", read(0, buf, sizeof(buf)) == 0);
    CHECK("read leaves buffer untouched", (unsigned char)buf[0] == 0xAA);

    struct iovec iov[1] = { { buf, sizeof(buf) } };
    CHECK("readv revoked fd returns 0", readv(0, iov, 1) == 0);

    /* writes are swallowed */
    CHECK("write revoked fd returns count", write(0, "hello", 5) == 5);
    struct iovec wv[2] = { { "ab", 2 }, { "cde", 3 } };
    CHECK("writev revoked fd returns total", writev(0, wv, 2) == 5);

    /* not a tty, no metadata */
    CHECK("isatty revoked fd is 0", isatty(0) == 0);
    struct stat st;
    errno = 0;
    CHECK("fstat revoked fd -> EACCES", fstat(0, &st) == -1 && errno == EACCES);

    /* /dev/null cannot be mapped */
    errno = 0;
    void *m = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, 0, 0);
    CHECK("mmap revoked fd -> ENODEV", m == MAP_FAILED && errno == ENODEV);

    /* fcntl(F_DUPFD) carries the revocation */
    int d = fcntl(0, F_DUPFD, 20);
    CHECK("F_DUPFD revoked fd", d >= 20);
    CHECK("read F_DUPFD'd fd returns 0", read(d, buf, sizeof(buf)) == 0);
    close(d);

    /* unrelated fds are untouched */
    int fd = open(REAL, O_CREAT | O_RDWR | O_TRUNC, 0644);
    CHECK("open real file", fd >= 0);
    CHECK("write real file", write(fd, "real data", 9) == 9);
    lseek(fd, 0, SEEK_SET);
    memset(buf, 0, sizeof(buf));
    CHECK("read real file", read(fd, buf, sizeof(buf)) == 9 && memcmp(buf, "real data", 9) == 0);
    CHECK("fstat real file", fstat(fd, &st) == 0 && st.st_size == 9);
    close(fd);
    unlink(REAL);

    printf("\nResult: %d/%d passed\n", total - failures, total);
    return failures ? 1 : 0;
}
