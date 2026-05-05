/* fork_pipe_race_test.c — regression for the fork/pipe-EOF race.
 *
 * Before the fix, fork_handler bumped pipe refcounts AFTER
 * forward_syscall(SYS_CLONE), but the child cage starts running as
 * soon as the clone returns.  If the child closed an inherited write
 * end before the parent's bump, write_refs hit 0 transiently and
 * decr_write_ref permanently latched eof=true.  The parent's later
 * write succeeded but the child's read returned 0 instead of the
 * data — pipepong's "Child received 0 instead of 1" pattern.
 *
 * This test reproduces the race by:
 *   1. Creating a parent_to_child pipe before fork.
 *   2. Forking.
 *   3. Child immediately closes the write end of parent_to_child
 *      (the side it doesn't need), then reads.
 *   4. Parent writes a known byte and waits for the child to confirm.
 *
 * If the bump is post-fork, step 3's close drives write_refs from 1
 * (the parent's only fd) → 0, latches eof.  Then step 4's write goes
 * to a buffer the reader will flag as EOF.  Result: child reads 0.
 *
 * With the fix, step 1 leaves write_refs=1 in the parent.  Pre-bump
 * during fork makes it 2.  Child's close drops it to 1.  Parent's
 * write succeeds.  Child reads the byte.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

int main(void) {
    int p[2];
    if (pipe(p) < 0) {
        perror("pipe");
        return 1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    }

    if (pid == 0) {
        /* Child: close the write end and read.  If the race fires,
         * write_refs hits 0 → eof latched → read returns 0 even after
         * the parent writes. */
        close(p[1]);
        unsigned char buf = 0;
        ssize_t n = read(p[0], &buf, 1);
        if (n != 1) {
            fprintf(stderr, "child read returned %zd (expected 1) — eof race latched\n", n);
            _exit(2);
        }
        if (buf != 0xAB) {
            fprintf(stderr, "child read 0x%02x (expected 0xAB)\n", buf);
            _exit(3);
        }
        close(p[0]);
        _exit(0);
    }

    /* Parent: close read end, write a marker byte, wait. */
    close(p[0]);
    unsigned char marker = 0xAB;
    ssize_t w = write(p[1], &marker, 1);
    if (w != 1) {
        fprintf(stderr, "parent write returned %zd\n", w);
        return 1;
    }
    close(p[1]);

    int status = 0;
    if (waitpid(pid, &status, 0) != pid) {
        perror("waitpid");
        return 1;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "child exited with status 0x%x\n", status);
        return 1;
    }

    printf("fork_pipe_race_test: PASS\n");
    return 0;
}
