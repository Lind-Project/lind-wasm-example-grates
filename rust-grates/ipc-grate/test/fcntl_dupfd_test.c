/* fcntl_dupfd_test.c — regression for F_DUPFD / F_DUPFD_CLOEXEC.
 *
 * Two bugs:
 *
 * 1. F_DUPFD on an FDKIND_KERNEL fd previously delegated to dup_handler,
 *    which calls SYS_DUP — losing the arg3 minimum-fd parameter.  And
 *    the runtime's new vfd was never registered in the grate's fdtable,
 *    so subsequent fcntl(newfd, ...) returned EBADF.
 *
 * 2. F_DUPFD_CLOEXEC was not a recognized op in the IPC dispatch and
 *    fell through to forward_with_fd1, which forwarded to the runtime
 *    but again never registered the result in the grate's fdtable.
 *
 * Now both ops are handled at the top of fcntl_handler and register the
 * new vfd ≥ arg3 on the grate side.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

static int fail_count = 0;
#define EXPECT(cond, msg) do { \
    if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); fail_count++; } \
} while (0)

int main(void) {
    int fd = open("/tmp/fcntl_dupfd_test.tmp", O_CREAT | O_RDWR | O_TRUNC, 0644);
    EXPECT(fd >= 0, "open temp file");
    if (fd < 0) return 1;

    /* F_DUPFD with min=100 */
    int dup_fd = fcntl(fd, F_DUPFD, 100);
    EXPECT(dup_fd >= 100, "fcntl(F_DUPFD, 100) returned >= 100");
    if (dup_fd >= 0) {
        /* Subsequent fcntl on the dup'd fd must work — this is the EBADF bug. */
        int flags = fcntl(dup_fd, F_GETFD);
        EXPECT(flags >= 0, "fcntl(dup_fd, F_GETFD) succeeded (was EBADF)");
        EXPECT((flags & FD_CLOEXEC) == 0,
               "F_DUPFD does not set FD_CLOEXEC");

        /* And read/write through the dup must also work. */
        if (write(dup_fd, "x", 1) != 1) {
            fprintf(stderr, "FAIL: write to dup_fd\n"); fail_count++;
        }
        close(dup_fd);
    }

    /* F_DUPFD_CLOEXEC with min=200 */
    int dup_cex = fcntl(fd, F_DUPFD_CLOEXEC, 200);
    EXPECT(dup_cex >= 200, "fcntl(F_DUPFD_CLOEXEC, 200) returned >= 200");
    if (dup_cex >= 0) {
        int flags = fcntl(dup_cex, F_GETFD);
        EXPECT(flags >= 0, "fcntl(dup_cex, F_GETFD) succeeded");
        EXPECT((flags & FD_CLOEXEC) != 0,
               "F_DUPFD_CLOEXEC sets FD_CLOEXEC");
        close(dup_cex);
    }

    close(fd);
    unlink("/tmp/fcntl_dupfd_test.tmp");

    if (fail_count == 0) {
        printf("fcntl_dupfd_test: PASS\n");
        return 0;
    }
    fprintf(stderr, "fcntl_dupfd_test: %d failures\n", fail_count);
    return 1;
}
