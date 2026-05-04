/* select_pipe_test.c — direct test for select() on an IPC pipe.
 *
 * Mirrors poll_pipe_test but for select().  Create a pipe, write a
 * byte, select on the read end with POLLIN-equivalent.  Verify
 * FD_ISSET(read_fd, &readfds).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/select.h>

int main(void) {
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        fprintf(stderr, "pipe failed: errno=%d\n", errno);
        return 1;
    }

    char b = 'X';
    ssize_t nw = write(pipefd[1], &b, 1);
    if (nw != 1) {
        fprintf(stderr, "write returned %zd, errno=%d\n", nw, errno);
        return 2;
    }

    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(pipefd[0], &readfds);

    struct timeval tv = { .tv_sec = 0, .tv_usec = 500 * 1000 };  /* 500ms */
    int rc = select(pipefd[0] + 1, &readfds, NULL, NULL, &tv);

    if (rc == 0) {
        fprintf(stderr, "select TIMED OUT despite pipe having data\n");
        return 3;
    }
    if (rc < 0) {
        fprintf(stderr, "select returned -1 errno=%d\n", errno);
        return 4;
    }
    if (!FD_ISSET(pipefd[0], &readfds)) {
        fprintf(stderr, "select returned %d but read-end not in readfds\n", rc);
        return 5;
    }

    /* Drain the byte to confirm there's actually data there. */
    char rb = 0;
    ssize_t nr = read(pipefd[0], &rb, 1);
    if (nr != 1 || rb != 'X') {
        fprintf(stderr, "read mismatch: nr=%zd byte=0x%02x\n", nr, (unsigned char) rb);
        return 6;
    }

    printf("select_pipe_test: PASS (select saw read-end ready, byte verified)\n");
    close(pipefd[0]);
    close(pipefd[1]);
    return 0;
}
