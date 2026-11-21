/*
 * Run as: revoke-grate revoke_syscall_test.cwasm
 *
 * No startup revocations: everything is revoked at runtime through the
 * revoke syscall, both on this cage and on a forked child.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
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

int main(void) {
    char buf[64];
    int self = getpid();

    int fd = open(PATH, O_CREAT | O_RDWR | O_TRUNC, 0644);
    CHECK("open file", fd >= 0);
    CHECK("write before revoke", write(fd, "original", 8) == 8);

    /* ── argument errors ── */
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
    CHECK("failed revokes left fd alone", lseek(fd, 0, SEEK_SET) == 0 &&
          read(fd, buf, 8) == 8 && memcmp(buf, "original", 8) == 0);

    /* ── revoke own fd as /dev/null ── */
    int keep = dup(fd); /* duplicated before the revoke: stays live (slot semantics) */
    CHECK("revoke own fd", lind_revoke(self, fd, REVOKE_MODE_NULL) == 0);
    memset(buf, 0xAA, sizeof(buf));
    CHECK("revoked fd reads EOF", read(fd, buf, sizeof(buf)) == 0);
    CHECK("revoked fd swallows writes", write(fd, "CLOBBER", 7) == 7);
    CHECK("file unchanged by swallowed write", file_is("original"));
    CHECK("earlier dup is still live", lseek(keep, 0, SEEK_SET) == 0 &&
          read(keep, buf, 8) == 8 && memcmp(buf, "original", 8) == 0);
    CHECK("revoking again is fine", lind_revoke(self, fd, REVOKE_MODE_NULL) == 0);
    CHECK("close revoked fd", close(fd) == 0);
    close(keep);

    /* ── revoke own fd as /dev/zero ── */
    fd = open(PATH, O_RDONLY);
    CHECK("reopen file", fd >= 0);
    CHECK("revoke as zero", lind_revoke(self, fd, REVOKE_MODE_ZERO) == 0);
    memset(buf, 0xAA, sizeof(buf));
    CHECK("zero-revoked fd reads zeros", read(fd, buf, 16) == 16 && all_zero(buf, 16));
    close(fd);

    /* ── revoke a forked child's fd from the parent ── */
    fd = open(PATH, O_RDONLY);
    int go[2];
    CHECK("pipe", pipe(go) == 0);
    pid_t child = fork();
    if (child == 0) {
        char c, cbuf[16];
        close(go[1]);
        if (read(go[0], &c, 1) != 1) _exit(2); /* wait for the parent's revoke */
        memset(cbuf, 0xAA, sizeof(cbuf));
        _exit(read(fd, cbuf, sizeof(cbuf)) == 0 ? 0 : 1);
    }
    close(go[0]);
    CHECK("revoke child's fd", lind_revoke(child, fd, REVOKE_MODE_NULL) == 0);
    write(go[1], "g", 1);
    int status = 0;
    waitpid(child, &status, 0);
    CHECK("child sees its fd revoked", WIFEXITED(status) && WEXITSTATUS(status) == 0);
    memset(buf, 0, sizeof(buf));
    CHECK("parent's copy is unaffected",
          read(fd, buf, 8) == 8 && memcmp(buf, "original", 8) == 0);
    close(fd);
    close(go[1]);

    errno = 0;
    CHECK("exited child -> ESRCH", lind_revoke(child, 0, REVOKE_MODE_NULL) == -1 && errno == ESRCH);

    unlink(PATH);
    printf("\nResult: %d/%d passed\n", total - failures, total);
    return failures ? 1 : 0;
}
