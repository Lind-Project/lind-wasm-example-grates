/* sock_cloexec_test.c — regression for SOCK_CLOEXEC across IPC sockets.
 *
 * Three IPC paths used to hardcode cloexec=false on the grate-side
 * fdtable entry, so fcntl(F_GETFD) on the resulting fd reported
 * cloexec=0 even when the user passed SOCK_CLOEXEC:
 *
 *   1. socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC)
 *   2. socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC)
 *   3. AF_INET loopback bind/connect take-over (FDKIND_KERNEL → IPC_SOCKET
 *      conversion overwrote the entry's cloexec bit)
 *
 * This test covers (1) and (2).  The full AF_INET take-over path requires
 * a server/client and is covered by the lind-wasm harness's accept4.c.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>

static int fail_count = 0;
#define EXPECT(cond, msg) do { \
    if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); fail_count++; } \
} while (0)

int main(void) {
    /* (1) socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0) */
    int s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    EXPECT(s >= 0, "socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC) returned >= 0");
    if (s >= 0) {
        int flags = fcntl(s, F_GETFD);
        EXPECT(flags >= 0, "fcntl(F_GETFD) on cloexec AF_UNIX socket succeeds");
        EXPECT((flags & FD_CLOEXEC) != 0,
               "FD_CLOEXEC set after socket(AF_UNIX, SOCK_CLOEXEC)");
        close(s);
    }

    /* socket(AF_UNIX, SOCK_STREAM, 0) — without SOCK_CLOEXEC, cloexec must NOT be set */
    int s_nocex = socket(AF_UNIX, SOCK_STREAM, 0);
    EXPECT(s_nocex >= 0, "socket(AF_UNIX, SOCK_STREAM) returned >= 0");
    if (s_nocex >= 0) {
        int flags = fcntl(s_nocex, F_GETFD);
        EXPECT(flags >= 0, "fcntl(F_GETFD) on plain AF_UNIX socket succeeds");
        EXPECT((flags & FD_CLOEXEC) == 0,
               "FD_CLOEXEC NOT set without SOCK_CLOEXEC");
        close(s_nocex);
    }

    /* (2) socketpair with SOCK_CLOEXEC */
    int sv[2];
    int rc = socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv);
    EXPECT(rc == 0, "socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC) returned 0");
    if (rc == 0) {
        int f0 = fcntl(sv[0], F_GETFD);
        int f1 = fcntl(sv[1], F_GETFD);
        EXPECT(f0 >= 0 && (f0 & FD_CLOEXEC), "socketpair[0] has FD_CLOEXEC");
        EXPECT(f1 >= 0 && (f1 & FD_CLOEXEC), "socketpair[1] has FD_CLOEXEC");
        close(sv[0]);
        close(sv[1]);
    }

    if (fail_count == 0) {
        printf("sock_cloexec_test: PASS\n");
        return 0;
    }
    fprintf(stderr, "sock_cloexec_test: %d failures\n", fail_count);
    return 1;
}
