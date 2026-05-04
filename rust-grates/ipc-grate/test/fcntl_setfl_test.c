/* fcntl_setfl_test.c — regression for F_SETFL access-mode preservation.
 *
 * Postgres calls fcntl(F_SETFL, O_NONBLOCK) on its self-pipe ends.
 * Earlier we had a bug where this overwrote perfdinfo entirely,
 * wiping the O_RDONLY/O_WRONLY access-mode bits we use to distinguish
 * pipe read-end from write-end.  Fixed in commit 942c8b0.  This test
 * exercises the path:
 *
 *   1. pipe(p) — read end gets O_RDONLY, write end gets O_WRONLY
 *   2. F_GETFL on each — sanity: access mode is correct
 *   3. F_SETFL O_NONBLOCK on each
 *   4. F_GETFL on each — access mode must STILL be correct,
 *      O_NONBLOCK must now be set
 *   5. write to write end, read from read end — must still work
 *      (broken access-mode would make our handler return EBADF)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#define O_NONBLOCK 04000  /* same value as Linux */
#define O_ACCMODE  03

static int fail_count = 0;
#define EXPECT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s\n", msg); \
        fail_count++; \
    } \
} while (0)

int main(void) {
    int p[2];
    if (pipe(p) != 0) {
        fprintf(stderr, "pipe failed: errno=%d\n", errno);
        return 1;
    }

    int read_flags  = fcntl(p[0], F_GETFL, 0);
    int write_flags = fcntl(p[1], F_GETFL, 0);
    EXPECT((read_flags  & O_ACCMODE) == 0, "read end access mode != O_RDONLY before F_SETFL");
    EXPECT((write_flags & O_ACCMODE) == 1, "write end access mode != O_WRONLY before F_SETFL");

    /* Set O_NONBLOCK on both. */
    int rc;
    rc = fcntl(p[0], F_SETFL, O_NONBLOCK);
    EXPECT(rc == 0, "F_SETFL O_NONBLOCK on read end failed");
    rc = fcntl(p[1], F_SETFL, O_NONBLOCK);
    EXPECT(rc == 0, "F_SETFL O_NONBLOCK on write end failed");

    /* Re-read flags and check both access mode AND O_NONBLOCK. */
    read_flags  = fcntl(p[0], F_GETFL, 0);
    write_flags = fcntl(p[1], F_GETFL, 0);
    printf("post-F_SETFL: read_flags=0x%x write_flags=0x%x\n",
           read_flags, write_flags);

    EXPECT((read_flags  & O_ACCMODE) == 0,
           "read end access mode CLOBBERED by F_SETFL (regression)");
    EXPECT((write_flags & O_ACCMODE) == 1,
           "write end access mode CLOBBERED by F_SETFL (regression)");
    EXPECT((read_flags  & O_NONBLOCK) != 0,
           "O_NONBLOCK not set on read end after F_SETFL");
    EXPECT((write_flags & O_NONBLOCK) != 0,
           "O_NONBLOCK not set on write end after F_SETFL");

    /* Write to write end and read from read end — verifies our
     * is_read_end / is_write_end checks still pass after F_SETFL. */
    char b = 'Z';
    ssize_t nw = write(p[1], &b, 1);
    EXPECT(nw == 1, "write to write-end after F_SETFL returned wrong count (EBADF would be -1)");

    char rb = 0;
    ssize_t nr = read(p[0], &rb, 1);
    EXPECT(nr == 1 && rb == 'Z', "read from read-end after F_SETFL returned wrong data");

    close(p[0]);
    close(p[1]);

    if (fail_count == 0) {
        printf("fcntl_setfl_test: PASS\n");
        return 0;
    }
    printf("fcntl_setfl_test: %d failures\n", fail_count);
    return 1;
}
