/* file_collision_reader.c — Helper for the fd-collision test.
 *
 * The parent execs this binary with leaked IPC pipe fds still in the
 * grate's fdtable. The kernel knows nothing about those pipes, so the
 * first open() here will return a low fd (typically 3) that overlaps
 * a stale grate IPC entry.
 *
 * If the IPC grate's exec_handler did NOT clean up its fdtable, the
 * grate intercepts read/write on those kernel-allocated fds and routes
 * them to dead pipes — typically returning EBADF (write to read-end /
 * read from write-end), short reads, or zero bytes. Any of those make
 * the verify step below fail.
 *
 * Open several files in succession to maximize the chance of hitting a
 * collided fd, since we don't know the exact numbering the kernel will
 * choose.
 *
 * Exit codes: 0 on success, non-zero on any I/O mismatch.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#define NFILES 6

int main(void) {
    const char *pattern = "HELLO_NO_COLLISION_0123456789";
    size_t plen = strlen(pattern);

    int fds[NFILES];
    char paths[NFILES][64];

    for (int i = 0; i < NFILES; i++) {
        snprintf(paths[i], sizeof(paths[i]), "/tmp/ipc_collision_%d.tmp", i);
        fds[i] = open(paths[i], O_RDWR | O_CREAT | O_TRUNC, 0644);
        if (fds[i] < 0) {
            fprintf(stderr, "open(%s) failed: errno=%d\n", paths[i], errno);
            return 2;
        }

        ssize_t nw = write(fds[i], pattern, plen);
        if (nw != (ssize_t)plen) {
            fprintf(stderr, "write fd=%d returned %zd (expected %zu) errno=%d\n",
                    fds[i], nw, plen, errno);
            return 1;
        }

        if (lseek(fds[i], 0, SEEK_SET) < 0) {
            fprintf(stderr, "lseek fd=%d failed: errno=%d\n", fds[i], errno);
            return 2;
        }

        char buf[64] = {0};
        ssize_t nr = read(fds[i], buf, sizeof(buf) - 1);
        if (nr != (ssize_t)plen) {
            fprintf(stderr, "read fd=%d returned %zd (expected %zu) errno=%d\n",
                    fds[i], nr, plen, errno);
            return 1;
        }
        if (memcmp(buf, pattern, plen) != 0) {
            fprintf(stderr, "fd=%d content mismatch: got \"%s\"\n", fds[i], buf);
            return 1;
        }
    }

    for (int i = 0; i < NFILES; i++) {
        close(fds[i]);
        unlink(paths[i]);
    }
    return 0;
}
