/* ipc_test.c — Test binary for the IPC grate.
 *
 * Exercises pipes, unix domain sockets, and fd lifecycle through the
 * IPC grate's userspace implementation. All IPC happens through in-memory
 * ring buffers — no kernel pipe/socket calls.
 *
 * Expected invocation:
 *   lind-wasm ipc-grate.cwasm -- ipc_test.cwasm
 *
 * Each test prints PASS/FAIL. Exit code 0 if all pass.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>

static int tests_run = 0;
static int tests_passed = 0;

#define CHECK(desc, cond) do { \
    tests_run++; \
    if (cond) { \
        printf("  PASS: %s\n", desc); \
        tests_passed++; \
    } else { \
        printf("  FAIL: %s (errno=%d)\n", desc, errno); \
    } \
} while (0)

/* ── Test 1: Basic pipe read/write ─────────────────────────────────── */

static void test_pipe_basic(void) {
    printf("\n[test_pipe_basic]\n");

    int pipefd[2];
    int ret = pipe(pipefd);
    CHECK("pipe() succeeds", ret == 0);
    if (ret != 0) return;

    CHECK("read fd is valid", pipefd[0] >= 0);
    CHECK("write fd is valid", pipefd[1] >= 0);
    CHECK("read and write fds differ", pipefd[0] != pipefd[1]);

    const char *msg = "hello pipe";
    ssize_t nw = write(pipefd[1], msg, strlen(msg));
    CHECK("write returns correct count", nw == (ssize_t)strlen(msg));

    char buf[64] = {0};
    ssize_t nr = read(pipefd[0], buf, sizeof(buf));
    CHECK("read returns correct count", nr == (ssize_t)strlen(msg));
    CHECK("data matches", memcmp(buf, msg, strlen(msg)) == 0);

    close(pipefd[0]);
    close(pipefd[1]);
}

/* ── Test 2: EOF when last writer closes ───────────────────────────── */

static void test_pipe_eof(void) {
    printf("\n[test_pipe_eof]\n");

    int pipefd[2];
    pipe(pipefd);

    /* Write some data, then close the write end. */
    write(pipefd[1], "data", 4);
    close(pipefd[1]);

    /* Read should get the data. */
    char buf[64] = {0};
    ssize_t nr = read(pipefd[0], buf, sizeof(buf));
    CHECK("read gets data before EOF", nr == 4);

    /* Next read should return 0 (EOF). */
    nr = read(pipefd[0], buf, sizeof(buf));
    CHECK("read returns 0 (EOF) after writer closes", nr == 0);

    close(pipefd[0]);
}

/* ── Test 3: Large transfer through pipe ───────────────────────────── */

static void test_pipe_large(void) {
    printf("\n[test_pipe_large]\n");

    int pipefd[2];
    pipe(pipefd);

    /* Write 4096 bytes in chunks. */
    char wbuf[4096];
    for (int i = 0; i < 4096; i++) {
        wbuf[i] = 'A' + (i % 26);
    }

    /* Fork: child writes, parent reads. This tests that the pipe
     * works across fork with correct fd inheritance and refcounts. */
    pid_t pid = fork();
    if (pid == 0) {
        /* Child: close read end, write all data, close write end. */
        close(pipefd[0]);
        ssize_t total = 0;
        while (total < 4096) {
            ssize_t n = write(pipefd[1], wbuf + total, 4096 - total);
            if (n <= 0) break;
            total += n;
        }
        close(pipefd[1]);
        _exit(0);
    }

    /* Parent: close write end, read all data. */
    close(pipefd[1]);

    char rbuf[4096] = {0};
    ssize_t total = 0;
    while (total < 4096) {
        ssize_t n = read(pipefd[0], rbuf + total, 4096 - total);
        if (n <= 0) break;
        total += n;
    }

    CHECK("read 4096 bytes total", total == 4096);
    CHECK("data matches", memcmp(rbuf, wbuf, 4096) == 0);

    close(pipefd[0]);
    waitpid(pid, NULL, 0);
}

/* ── Test 4: Dup preserves pipe direction ──────────────────────────── */

static void test_pipe_dup(void) {
    printf("\n[test_pipe_dup]\n");

    int pipefd[2];
    pipe(pipefd);

    /* Dup the write end. */
    int wfd2 = dup(pipefd[1]);
    CHECK("dup write end succeeds", wfd2 >= 0);

    /* Write through the dup'd fd. */
    write(wfd2, "dup test", 8);

    /* Read from the original read end. */
    char buf[64] = {0};
    ssize_t nr = read(pipefd[0], buf, sizeof(buf));
    CHECK("read through original read fd", nr == 8);
    CHECK("data matches", memcmp(buf, "dup test", 8) == 0);

    /* Close original write end — pipe should NOT get EOF because
     * the dup'd write end is still open. */
    close(pipefd[1]);

    write(wfd2, "still", 5);
    nr = read(pipefd[0], buf, sizeof(buf));
    CHECK("pipe still writable after closing one write end", nr == 5);

    /* Close the dup'd write end — NOW pipe should EOF. */
    close(wfd2);
    nr = read(pipefd[0], buf, sizeof(buf));
    CHECK("EOF after all write ends closed", nr == 0);

    close(pipefd[0]);
}

/* ── Test 5: Dup2 replaces target fd ───────────────────────────────── */

static void test_pipe_dup2(void) {
    printf("\n[test_pipe_dup2]\n");

    int pipefd[2];
    pipe(pipefd);

    /* Dup2 the write end onto fd 50. */
    int ret = dup2(pipefd[1], 50);
    CHECK("dup2 succeeds", ret == 50);

    write(50, "dup2 data", 9);

    char buf[64] = {0};
    ssize_t nr = read(pipefd[0], buf, sizeof(buf));
    CHECK("read after dup2 write", nr == 9);
    CHECK("data matches", memcmp(buf, "dup2 data", 9) == 0);

    close(50);
    close(pipefd[0]);
    close(pipefd[1]);
}

/* ── Test 6: Unix socketpair bidirectional ──────────────────────────── */

static void test_socketpair(void) {
    printf("\n[test_socketpair]\n");

    int sv[2];
    int ret = socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    CHECK("socketpair() succeeds", ret == 0);
    if (ret != 0) return;

    /* s1 → s2 */
    write(sv[0], "hello", 5);
    char buf[64] = {0};
    ssize_t nr = read(sv[1], buf, sizeof(buf));
    CHECK("s1 → s2: read gets data", nr == 5);
    CHECK("s1 → s2: data matches", memcmp(buf, "hello", 5) == 0);

    /* s2 → s1 */
    write(sv[1], "world", 5);
    memset(buf, 0, sizeof(buf));
    nr = read(sv[0], buf, sizeof(buf));
    CHECK("s2 → s1: read gets data", nr == 5);
    CHECK("s2 → s1: data matches", memcmp(buf, "world", 5) == 0);

    close(sv[0]);
    close(sv[1]);
}

/* ── Test 7: Unix socket connect/accept ────────────────────────────── */

static void test_unix_connect_accept(void) {
    printf("\n[test_unix_connect_accept]\n");

    /* Server: socket, bind, listen. */
    int server = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK("server socket()", server >= 0);
    if (server < 0) return;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, "/tmp/ipc_test.sock");

    int ret = bind(server, (struct sockaddr *)&addr, sizeof(addr));
    CHECK("bind()", ret == 0);

    ret = listen(server, 5);
    CHECK("listen()", ret == 0);

    /* Fork: child connects, parent accepts. */
    pid_t pid = fork();
    if (pid == 0) {
        /* Child: connect to server. */
        close(server);

        int client = socket(AF_UNIX, SOCK_STREAM, 0);
        struct sockaddr_un caddr;
        memset(&caddr, 0, sizeof(caddr));
        caddr.sun_family = AF_UNIX;
        strcpy(caddr.sun_path, "/tmp/ipc_test.sock");

        int cret = connect(client, (struct sockaddr *)&caddr, sizeof(caddr));
        if (cret < 0) { _exit(1); }

        write(client, "from child", 10);

        char buf[64] = {0};
        read(client, buf, sizeof(buf));

        close(client);
        _exit(0);
    }

    /* Parent: accept connection. */
    int conn = accept(server, NULL, NULL);
    CHECK("accept() returns valid fd", conn >= 0);

    if (conn >= 0) {
        char buf[64] = {0};
        ssize_t nr = read(conn, buf, sizeof(buf));
        CHECK("read from accepted connection", nr == 10);
        CHECK("data from child matches", memcmp(buf, "from child", 10) == 0);

        write(conn, "from parent", 11);
        close(conn);
    }

    close(server);
    waitpid(pid, NULL, 0);
}

/* ── Test 8: Fork inherits pipe fds correctly ──────────────────────── */

static void test_fork_pipe_inherit(void) {
    printf("\n[test_fork_pipe_inherit]\n");

    int pipefd[2];
    pipe(pipefd);

    pid_t pid = fork();
    if (pid == 0) {
        /* Child: close read end, write, close write end. */
        close(pipefd[0]);
        write(pipefd[1], "child data", 10);
        close(pipefd[1]);
        _exit(0);
    }

    /* Parent: close write end, read, verify. */
    close(pipefd[1]);

    char buf[64] = {0};
    ssize_t nr = read(pipefd[0], buf, sizeof(buf));
    CHECK("parent reads child's data", nr == 10);
    CHECK("data matches", memcmp(buf, "child data", 10) == 0);

    /* After child exits and closes its write end, parent should get EOF. */
    waitpid(pid, NULL, 0);
    nr = read(pipefd[0], buf, sizeof(buf));
    CHECK("EOF after child exits", nr == 0);

    close(pipefd[0]);
}

/* ── Test 9: Non-pipe fd forwards transparently ────────────────────── */

static void test_non_pipe_forward(void) {
    printf("\n[test_non_pipe_forward]\n");

    /* Write to stdout — should go through to the real fd, not the
     * IPC grate's pipe handler. If this prints, forwarding works. */
    const char *msg = "  PASS: non-pipe stdout write forwarded correctly\n";
    ssize_t nw = write(1, msg, strlen(msg));
    tests_run++;
    if (nw > 0) tests_passed++;
}

/* ── Test 10: Pipe with fcntl F_GETFL ──────────────────────────────── */

static void test_fcntl(void) {
    printf("\n[test_fcntl]\n");

    int pipefd[2];
    pipe(pipefd);

    int flags = fcntl(pipefd[0], F_GETFL);
    CHECK("fcntl F_GETFL on read end returns O_RDONLY", (flags & O_ACCMODE) == O_RDONLY);

    flags = fcntl(pipefd[1], F_GETFL);
    CHECK("fcntl F_GETFL on write end returns O_WRONLY", (flags & O_ACCMODE) == O_WRONLY);

    close(pipefd[0]);
    close(pipefd[1]);
}

/* ── Test 11: Shutdown on socketpair ───────────────────────────────── */

static void test_shutdown(void) {
    printf("\n[test_shutdown]\n");

    int sv[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);

    /* Shut down write direction on sv[0]. */
    shutdown(sv[0], SHUT_WR);

    /* sv[1] should get EOF on read (peer shut down its write). */
    char buf[64];
    ssize_t nr = read(sv[1], buf, sizeof(buf));
    CHECK("read returns 0 after peer SHUT_WR", nr == 0);

    /* sv[0] can still read (only write was shut down). */
    write(sv[1], "still open", 10);
    nr = read(sv[0], buf, sizeof(buf));
    CHECK("can still read after own SHUT_WR", nr == 10);

    close(sv[0]);
    close(sv[1]);
}

/* ── Main ──────────────────────────────────────────────────────────── */

int main(void) {
    printf("=== ipc grate test ===\n");

    test_pipe_basic();
    test_pipe_eof();
    test_pipe_large();
    test_pipe_dup();
    test_pipe_dup2();
    test_socketpair();
    test_unix_connect_accept();
    test_fork_pipe_inherit();
    test_non_pipe_forward();
    test_fcntl();
    test_shutdown();

    printf("\n=== results: %d/%d passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
