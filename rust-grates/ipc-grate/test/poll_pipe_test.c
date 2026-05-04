/* poll_pipe_test.c — direct test for poll() on an IPC pipe.
 *
 * This is the self-pipe trick that postgres uses: create a pipe,
 * write a byte to it, then poll() the read end for POLLIN.  Under a
 * working pipe, poll returns immediately with POLLIN set.
 *
 * The IPC grate doesn't intercept SYS_POLL, so poll forwards to
 * RawPOSIX whose fdtables knows nothing about our userspace pipe.
 * Expected (broken) behavior: poll either times out (returns 0) or
 * blocks forever, even though the pipe has data.
 *
 * Usage:
 *   lind-wasm --enable-fpcast /grates/ipc-grate.cwasm poll_pipe_test.cwasm
 *
 * Exit codes:
 *   0  — pass: poll correctly reported POLLIN
 *   1  — pipe() failed
 *   2  — write to pipe failed
 *   3  — poll returned 0 (timeout)  -- broken poll integration
 *   4  — poll returned negative (error)
 *   5  — poll returned > 0 but POLLIN wasn't set
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>

int main(void) {
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        fprintf(stderr, "pipe failed: errno=%d\n", errno);
        return 1;
    }

    /* Put a byte into the write end so poll on the read end should
     * see POLLIN immediately. */
    char b = 'X';
    ssize_t nw = write(pipefd[1], &b, 1);
    if (nw != 1) {
        fprintf(stderr, "write to pipe returned %zd, errno=%d\n", nw, errno);
        return 2;
    }

    struct pollfd pfd = {
        .fd = pipefd[0],
        .events = POLLIN,
        .revents = 0,
    };

    /* 500ms timeout — generous; a working poll() returns ~immediately. */
    int rc = poll(&pfd, 1, 500);

    if (rc == 0) {
        fprintf(stderr, "poll TIMED OUT despite pipe having data — "
                        "poll integration with IPC pipe is broken\n");
        return 3;
    }
    if (rc < 0) {
        fprintf(stderr, "poll returned -1, errno=%d\n", errno);
        return 4;
    }
    if (!(pfd.revents & POLLIN)) {
        fprintf(stderr, "poll returned %d but revents=0x%x (POLLIN not set)\n",
                rc, pfd.revents);
        return 5;
    }

    printf("poll_pipe_test: PASS (poll saw POLLIN on pipe with data)\n");

    close(pipefd[0]);
    close(pipefd[1]);
    return 0;
}
