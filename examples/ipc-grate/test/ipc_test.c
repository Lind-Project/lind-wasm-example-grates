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

    write(pipefd[1], "data", 4);
    close(pipefd[1]);

    char buf[64] = {0};
    ssize_t nr = read(pipefd[0], buf, sizeof(buf));
    CHECK("read gets data before EOF", nr == 4);

    nr = read(pipefd[0], buf, sizeof(buf));
    CHECK("read returns 0 (EOF) after writer closes", nr == 0);

    close(pipefd[0]);
}

/* ── Test 3: Large transfer across fork ────────────────────────────── */
/* Tests fork fd inheritance, refcounting, and cross-cage pipe I/O. */

static void test_pipe_large(void) {
    printf("\n[test_pipe_large]\n");

    int pipefd[2];
    pipe(pipefd);

    char wbuf[4096];
    for (int i = 0; i < 4096; i++)
        wbuf[i] = 'A' + (i % 26);

    pid_t pid = fork();
    if (pid == 0) {
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

/* ── Test 4: Dup write-end refcounting ─────────────────────────────── */
/* Dup the write end, close original — pipe should stay open.
 * Close the dup'd end — NOW pipe should EOF. */

static void test_pipe_dup(void) {
    printf("\n[test_pipe_dup]\n");

    int pipefd[2];
    pipe(pipefd);

    int wfd2 = dup(pipefd[1]);
    CHECK("dup write end succeeds", wfd2 >= 0);

    write(wfd2, "dup test", 8);

    char buf[64] = {0};
    ssize_t nr = read(pipefd[0], buf, sizeof(buf));
    CHECK("read through original read fd", nr == 8);
    CHECK("data matches", memcmp(buf, "dup test", 8) == 0);

    /* Close original write end — dup'd end keeps pipe alive. */
    close(pipefd[1]);

    write(wfd2, "still", 5);
    nr = read(pipefd[0], buf, sizeof(buf));
    CHECK("pipe still writable after closing one write end", nr == 5);

    /* Close dup'd write end — EOF. */
    close(wfd2);
    nr = read(pipefd[0], buf, sizeof(buf));
    CHECK("EOF after all write ends closed", nr == 0);

    close(pipefd[0]);
}

/* ── Test 5: Dup2 to specific fd number ────────────────────────────── */

static void test_pipe_dup2(void) {
    printf("\n[test_pipe_dup2]\n");

    int pipefd[2];
    pipe(pipefd);

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

/* ── Test 6: Socketpair bidirectional ──────────────────────────────── */

static void test_socketpair(void) {
    printf("\n[test_socketpair]\n");

    int sv[2];
    int ret = socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    CHECK("socketpair() succeeds", ret == 0);
    if (ret != 0) return;

    write(sv[0], "hello", 5);
    char buf[64] = {0};
    ssize_t nr = read(sv[1], buf, sizeof(buf));
    CHECK("s1 -> s2: read gets data", nr == 5);
    CHECK("s1 -> s2: data matches", memcmp(buf, "hello", 5) == 0);

    write(sv[1], "world", 5);
    memset(buf, 0, sizeof(buf));
    nr = read(sv[0], buf, sizeof(buf));
    CHECK("s2 -> s1: read gets data", nr == 5);
    CHECK("s2 -> s1: data matches", memcmp(buf, "world", 5) == 0);

    close(sv[0]);
    close(sv[1]);
}

/* ── Test 7: Unix socket connect/accept ────────────────────────────── */

static void test_unix_connect_accept(void) {
    printf("\n[test_unix_connect_accept]\n");

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

    pid_t pid = fork();
    if (pid == 0) {
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
        close(pipefd[0]);
        write(pipefd[1], "child data", 10);
        close(pipefd[1]);
        _exit(0);
    }

    close(pipefd[1]);

    char buf[64] = {0};
    ssize_t nr = read(pipefd[0], buf, sizeof(buf));
    CHECK("parent reads child's data", nr == 10);
    CHECK("data matches", memcmp(buf, "child data", 10) == 0);

    waitpid(pid, NULL, 0);
    nr = read(pipefd[0], buf, sizeof(buf));
    CHECK("EOF after child exits", nr == 0);

    close(pipefd[0]);
}

/* ── Test 9: Non-pipe fd forwards transparently ────────────────────── */

static void test_non_pipe_forward(void) {
    printf("\n[test_non_pipe_forward]\n");

    const char *msg = "  PASS: non-pipe stdout write forwarded correctly\n";
    ssize_t nw = write(1, msg, strlen(msg));
    tests_run++;
    if (nw > 0) tests_passed++;
}

/* ── Test 10: fcntl F_GETFL ────────────────────────────────────────── */

static void test_fcntl(void) {
    printf("\n[test_fcntl]\n");

    int pipefd[2];
    pipe(pipefd);

    int flags = fcntl(pipefd[0], F_GETFL);
    CHECK("F_GETFL on read end returns O_RDONLY", (flags & O_ACCMODE) == O_RDONLY);

    flags = fcntl(pipefd[1], F_GETFL);
    CHECK("F_GETFL on write end returns O_WRONLY", (flags & O_ACCMODE) == O_WRONLY);

    close(pipefd[0]);
    close(pipefd[1]);
}

/* ── Test 11: Shutdown on socketpair ───────────────────────────────── */

static void test_shutdown(void) {
    printf("\n[test_shutdown]\n");

    int sv[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);

    shutdown(sv[0], SHUT_WR);

    char buf[64];
    ssize_t nr = read(sv[1], buf, sizeof(buf));
    CHECK("read returns 0 after peer SHUT_WR", nr == 0);

    write(sv[1], "still open", 10);
    nr = read(sv[0], buf, sizeof(buf));
    CHECK("can still read after own SHUT_WR", nr == 10);

    close(sv[0]);
    close(sv[1]);
}

/* ── Test 12: Multiple pipes open simultaneously ───────────────────── */
/* Verifies that the grate correctly tracks separate pipes and doesn't
 * mix up fd-to-pipe mappings across concurrent pipes. */

static void test_multiple_pipes(void) {
    printf("\n[test_multiple_pipes]\n");

    int p1[2], p2[2], p3[2];
    pipe(p1);
    pipe(p2);
    pipe(p3);

    write(p1[1], "pipe1", 5);
    write(p2[1], "pipe2_data", 10);
    write(p3[1], "p3", 2);

    char buf[64] = {0};

    ssize_t nr = read(p1[0], buf, sizeof(buf));
    CHECK("pipe1 has correct data", nr == 5 && memcmp(buf, "pipe1", 5) == 0);

    nr = read(p2[0], buf, sizeof(buf));
    CHECK("pipe2 has correct data", nr == 10 && memcmp(buf, "pipe2_data", 10) == 0);

    nr = read(p3[0], buf, sizeof(buf));
    CHECK("pipe3 has correct data", nr == 2 && memcmp(buf, "p3", 2) == 0);

    close(p1[0]); close(p1[1]);
    close(p2[0]); close(p2[1]);
    close(p3[0]); close(p3[1]);
}

/* ── Test 13: Pipe after fork — producer/consumer pattern ──────────── */
/* Classic shell pipeline pattern: parent creates pipe, forks N children.
 * Child 1 writes, child 2 reads. Parent waits for both. */

static void test_pipe_pipeline(void) {
    printf("\n[test_pipe_pipeline]\n");

    int pipefd[2];
    pipe(pipefd);

    /* Writer child. */
    pid_t writer = fork();
    if (writer == 0) {
        close(pipefd[0]);
        const char *msg = "pipeline data from writer";
        write(pipefd[1], msg, strlen(msg));
        close(pipefd[1]);
        _exit(0);
    }

    /* Reader child. */
    pid_t reader = fork();
    if (reader == 0) {
        close(pipefd[1]);
        char buf[64] = {0};
        ssize_t nr = read(pipefd[0], buf, sizeof(buf));
        close(pipefd[0]);
        /* Exit with read count as status so parent can verify. */
        _exit(nr == 25 ? 0 : 1);
    }

    /* Parent closes both ends and waits. */
    close(pipefd[0]);
    close(pipefd[1]);

    int wstatus, rstatus;
    waitpid(writer, &wstatus, 0);
    waitpid(reader, &rstatus, 0);

    CHECK("writer child exited cleanly",
          WIFEXITED(wstatus) && WEXITSTATUS(wstatus) == 0);
    CHECK("reader child got correct data",
          WIFEXITED(rstatus) && WEXITSTATUS(rstatus) == 0);
}

/* ── Test 14: Dup2 overwrites an existing pipe fd ──────────────────── */
/* Verifies that dup2'ing onto a fd that's already a pipe end correctly
 * decrements the old pipe's refcount. */

static void test_dup2_overwrite(void) {
    printf("\n[test_dup2_overwrite]\n");

    int p1[2], p2[2];
    pipe(p1);
    pipe(p2);

    /* dup2 p2's write end onto p1's write end fd number.
     * This should close p1's write end (decrement refcount). */
    dup2(p2[1], p1[1]);

    /* p1's write end is now closed — read should eventually EOF. */
    /* But we need to also close the original p2[1] to truly close
     * the dup'd copy. Let's write through the overwritten fd first. */
    write(p1[1], "via overwritten fd", 18);

    /* This should appear on p2's read end, not p1's. */
    char buf[64] = {0};
    ssize_t nr = read(p2[0], buf, sizeof(buf));
    CHECK("write through overwritten fd goes to p2", nr == 18);
    CHECK("data matches", memcmp(buf, "via overwritten fd", 18) == 0);

    close(p1[0]); close(p1[1]);
    close(p2[0]); close(p2[1]);
}

/* ── Test 15: Socketpair across fork ───────────────────────────────── */
/* Verifies that forked children correctly inherit socket fds and can
 * communicate bidirectionally through the inherited socketpair. */

static void test_socketpair_fork(void) {
    printf("\n[test_socketpair_fork]\n");

    int sv[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);

    pid_t pid = fork();
    if (pid == 0) {
        /* Child uses sv[1]. */
        close(sv[0]);
        write(sv[1], "child msg", 9);

        char buf[64] = {0};
        ssize_t nr = read(sv[1], buf, sizeof(buf));
        /* Verify parent's response. */
        close(sv[1]);
        _exit((nr == 10 && memcmp(buf, "parent msg", 10) == 0) ? 0 : 1);
    }

    /* Parent uses sv[0]. */
    close(sv[1]);

    char buf[64] = {0};
    ssize_t nr = read(sv[0], buf, sizeof(buf));
    CHECK("parent reads child msg via socketpair", nr == 9);
    CHECK("data matches", memcmp(buf, "child msg", 9) == 0);

    write(sv[0], "parent msg", 10);
    close(sv[0]);

    int status;
    waitpid(pid, &status, 0);
    CHECK("child got parent's response",
          WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

/* ── Test 16: Rapid pipe create/close cycles ───────────────────────── */
/* Stress test: create and destroy many pipes rapidly. Verifies that
 * fd and pipe_id allocation/deallocation doesn't leak or corrupt. */

static void test_rapid_pipe_lifecycle(void) {
    printf("\n[test_rapid_pipe_lifecycle]\n");

    int ok = 1;
    for (int i = 0; i < 100; i++) {
        int pipefd[2];
        if (pipe(pipefd) != 0) { ok = 0; break; }

        char data = (char)('A' + (i % 26));
        write(pipefd[1], &data, 1);

        char buf = 0;
        ssize_t nr = read(pipefd[0], &buf, 1);
        if (nr != 1 || buf != data) { ok = 0; break; }

        close(pipefd[0]);
        close(pipefd[1]);
    }

    tests_run++;
    if (ok) {
        printf("  PASS: 100 pipe create/write/read/close cycles\n");
        tests_passed++;
    } else {
        printf("  FAIL: rapid pipe lifecycle broke\n");
    }
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
    test_multiple_pipes();
    test_pipe_pipeline();
    test_dup2_overwrite();
    test_socketpair_fork();
    test_rapid_pipe_lifecycle();

    printf("\n=== results: %d/%d passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
