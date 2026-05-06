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
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/epoll.h>

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
    printf("  fork() returned %d\n", pid);
    if (pid == 0) {
        printf("  [child] about to close(server)\n");
        close(server);

        printf("  [child] about to socket()\n");
        int client = socket(AF_UNIX, SOCK_STREAM, 0);
        printf("  [child] socket() = %d\n", client);
        struct sockaddr_un caddr;
        memset(&caddr, 0, sizeof(caddr));
        caddr.sun_family = AF_UNIX;
        strcpy(caddr.sun_path, "/tmp/ipc_test.sock");

        printf("  [child] about to connect()\n");
        int cret = connect(client, (struct sockaddr *)&caddr, sizeof(caddr));
        printf("  [child] connect() = %d\n", cret);
        if (cret < 0) { _exit(1); }

        write(client, "from child", 10);

        char buf[64] = {0};
        read(client, buf, sizeof(buf));

        close(client);
        _exit(0);
    }

    printf("  [parent] about to accept()\n");
    int conn = accept(server, NULL, NULL);
    printf("  [parent] accept() = %d\n", conn);
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

/* ── Test 17: popen pattern — dup2 pipe to stdin then exec ────────── */
/* Simulates what popen("cmd", "w") does: parent writes to pipe,
 * child dup2's read end to stdin, execs a program that reads stdin.
 * Tests 4KB, 64KB (pipe buffer size), and 256KB transfers. */

static void test_popen_exec_helper(const char *desc, long nbytes) {
    int pipefd[2];
    pipe(pipefd);

    pid_t pid = fork();
    if (pid == 0) {
        /* Child: popen pattern — redirect pipe read end to stdin, exec reader */
        close(pipefd[1]);       /* close write end */
        dup2(pipefd[0], 0);     /* pipe read end -> stdin */
        close(pipefd[0]);       /* close original fd */

        /* exec the reader with expected byte count */
        char countbuf[32];
        snprintf(countbuf, sizeof(countbuf), "%ld", nbytes);
        execl("pipe_stdin_reader.cwasm", "pipe_stdin_reader.cwasm", countbuf, NULL);
        /* if exec fails */
        perror("execl failed");
        _exit(2);
    }

    /* Parent: write pattern data to pipe */
    close(pipefd[0]);

    char wbuf[4096];
    long total = 0;
    while (total < nbytes) {
        long chunk = nbytes - total;
        if (chunk > 4096) chunk = 4096;
        for (long i = 0; i < chunk; i++)
            wbuf[i] = 'A' + ((total + i) % 26);
        ssize_t nw = write(pipefd[1], wbuf, chunk);
        if (nw <= 0) break;
        total += nw;
    }
    close(pipefd[1]);

    int status;
    waitpid(pid, &status, 0);

    CHECK(desc, WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void test_popen_exec(void) {
    printf("\n[test_popen_exec]\n");

    test_popen_exec_helper("popen pattern: 4KB through exec'd stdin", 4096);
    test_popen_exec_helper("popen pattern: 64KB through exec'd stdin", 65536);
    test_popen_exec_helper("popen pattern: 256KB through exec'd stdin", 256 * 1024);
}

/* ── Test: basic file I/O through the IPC grate ───────────────────── */
/* Sanity check that the IPC grate's open/close/read/write handlers
 * correctly forward non-IPC file operations to the kernel.  No pipes,
 * no fork — just open a file, write a pattern, close, reopen, read,
 * verify. */

static void test_file_io_basic(void) {
    printf("\n[test_file_io_basic]\n");

    const char *path = "/tmp/ipc_grate_basic_io.tmp";
    const char *pattern = "ipc-grate-basic-file-io-check";
    size_t plen = strlen(pattern);

    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    CHECK("open(O_RDWR|O_CREAT) returns valid fd", fd >= 0);
    if (fd < 0) return;

    ssize_t nw = write(fd, pattern, plen);
    CHECK("write() to file returns full length", nw == (ssize_t)plen);

    CHECK("close(fd) succeeds", close(fd) == 0);

    fd = open(path, O_RDONLY);
    CHECK("reopen O_RDONLY returns valid fd", fd >= 0);
    if (fd < 0) { unlink(path); return; }

    char buf[64] = {0};
    ssize_t nr = read(fd, buf, sizeof(buf) - 1);
    CHECK("read() returns full length",
          nr == (ssize_t)plen && memcmp(buf, pattern, plen) == 0);

    CHECK("close(fd) after read succeeds", close(fd) == 0);

    unlink(path);
}

/* ── Test 17b: fd collision after exec ───────────────────────────── */
/* Parent creates a pipe and forks. Child deliberately leaks both pipe
 * fds (does not close them) and execs a helper that opens kernel files.
 * Without the exec_handler IPC cleanup, the grate's fdtable still holds
 * IPC entries on the inherited pipe fds; when the helper's open() returns
 * those same fd numbers from the kernel, read/write on them gets routed
 * to the dead pipe instead of the file, and the helper exits non-zero.
 */
static void test_fd_collision_after_exec(void) {
    printf("\n[test_fd_collision_after_exec]\n");

    int pipefd[2];
    if (pipe(pipefd) != 0) {
        printf("  FAIL: pipe() errno=%d\n", errno);
        tests_run++;
        return;
    }

    pid_t pid = fork();
    if (pid == 0) {
        /* Intentionally do NOT close pipefd[0]/pipefd[1].  The grate's
         * fdtable will still hold IPC pipe entries on those fd numbers
         * across the exec, shadowing kernel-allocated file fds in the
         * exec'd program. */
        execl("file_collision_reader.cwasm", "file_collision_reader.cwasm", NULL);
        perror("execl failed");
        _exit(2);
    }

    /* Parent: drop pipe ends so the child's read end (if it ever gets
     * used) hits EOF promptly. */
    close(pipefd[0]);
    close(pipefd[1]);

    int status;
    waitpid(pid, &status, 0);
    CHECK("file I/O after exec with leaked pipe fds",
          WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

/* ── Test 18: Large pipe transfer correctness ─────────────────────── */
/* Verifies byte-level correctness for transfers larger than the pipe
 * buffer (65KB). Tests 128KB and 512KB across a fork. */

static void test_large_pipe_correctness_helper(const char *desc, long nbytes) {
    int pipefd[2];
    pipe(pipefd);

    pid_t pid = fork();
    if (pid == 0) {
        /* Child: writer */
        close(pipefd[0]);
        char wbuf[4096];
        long total = 0;
        while (total < nbytes) {
            long chunk = nbytes - total;
            if (chunk > 4096) chunk = 4096;
            for (long i = 0; i < chunk; i++)
                wbuf[i] = 'A' + ((total + i) % 26);
            ssize_t nw = write(pipefd[1], wbuf, chunk);
            if (nw <= 0) _exit(1);
            total += nw;
        }
        close(pipefd[1]);
        _exit(0);
    }

    /* Parent: reader */
    close(pipefd[1]);

    char rbuf[4096];
    long total = 0;
    int ok = 1;
    while (total < nbytes) {
        ssize_t nr = read(pipefd[0], rbuf, sizeof(rbuf));
        if (nr <= 0) { ok = 0; break; }
        for (long i = 0; i < nr; i++) {
            char want = 'A' + ((total + i) % 26);
            if (rbuf[i] != want) { ok = 0; break; }
        }
        if (!ok) break;
        total += nr;
    }
    if (total != nbytes) ok = 0;

    close(pipefd[0]);
    waitpid(pid, NULL, 0);

    CHECK(desc, ok);
}

static void test_large_pipe_correctness(void) {
    printf("\n[test_large_pipe_correctness]\n");

    test_large_pipe_correctness_helper("128KB pipe transfer correct", 128 * 1024);
    test_large_pipe_correctness_helper("512KB pipe transfer correct", 512 * 1024);
}

/* ── Test: fcntl(F_SETFL) preserves access mode ───────────────────── */

static void test_fcntl_setfl_preservation(void) {
    printf("\n[test_fcntl_setfl_preservation]\n");

    int p[2];
    if (pipe(p) != 0) { printf("  FAIL: pipe()\n"); tests_run++; return; }

    int read_flags  = fcntl(p[0], F_GETFL, 0);
    int write_flags = fcntl(p[1], F_GETFL, 0);
    CHECK("read end is O_RDONLY before F_SETFL",  (read_flags  & O_ACCMODE) == O_RDONLY);
    CHECK("write end is O_WRONLY before F_SETFL", (write_flags & O_ACCMODE) == O_WRONLY);

    CHECK("F_SETFL O_NONBLOCK on read end",  fcntl(p[0], F_SETFL, O_NONBLOCK) == 0);
    CHECK("F_SETFL O_NONBLOCK on write end", fcntl(p[1], F_SETFL, O_NONBLOCK) == 0);

    read_flags  = fcntl(p[0], F_GETFL, 0);
    write_flags = fcntl(p[1], F_GETFL, 0);
    CHECK("read end access mode preserved after F_SETFL",
          (read_flags  & O_ACCMODE) == O_RDONLY);
    CHECK("write end access mode preserved after F_SETFL",
          (write_flags & O_ACCMODE) == O_WRONLY);
    CHECK("O_NONBLOCK set on read end after F_SETFL",
          (read_flags  & O_NONBLOCK) != 0);
    CHECK("O_NONBLOCK set on write end after F_SETFL",
          (write_flags & O_NONBLOCK) != 0);

    /* write/read still work — proves we didn't clobber direction bits. */
    char b = 'Z';
    CHECK("write to write-end after F_SETFL",  write(p[1], &b, 1) == 1);
    char rb = 0;
    CHECK("read from read-end after F_SETFL", read(p[0], &rb, 1) == 1 && rb == 'Z');

    close(p[0]);
    close(p[1]);
}

/* ── Test: fcntl F_DUPFD / F_DUPFD_CLOEXEC ────────────────────────── */

static void test_fcntl_dupfd(void) {
    printf("\n[test_fcntl_dupfd]\n");

    const char *path = "fcntl_dupfd_test.tmp";
    int fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0644);
    CHECK("open temp file for dup test", fd >= 0);
    if (fd < 0) return;

    int dup_fd = fcntl(fd, F_DUPFD, 100);
    CHECK("fcntl(F_DUPFD, 100) returns >= 100", dup_fd >= 100);
    if (dup_fd >= 0) {
        int flags = fcntl(dup_fd, F_GETFD);
        CHECK("fcntl(F_GETFD) on dup'd fd succeeds (was EBADF)", flags >= 0);
        CHECK("F_DUPFD does not set FD_CLOEXEC",
              flags >= 0 && (flags & FD_CLOEXEC) == 0);
        CHECK("write through dup'd fd works", write(dup_fd, "x", 1) == 1);
        close(dup_fd);
    }

    int dup_cex = fcntl(fd, F_DUPFD_CLOEXEC, 200);
    CHECK("fcntl(F_DUPFD_CLOEXEC, 200) returns >= 200", dup_cex >= 200);
    if (dup_cex >= 0) {
        int flags = fcntl(dup_cex, F_GETFD);
        CHECK("F_DUPFD_CLOEXEC sets FD_CLOEXEC",
              flags >= 0 && (flags & FD_CLOEXEC) != 0);
        close(dup_cex);
    }

    close(fd);
    unlink(path);
}

/* ── Test: SOCK_CLOEXEC across IPC sockets ───────────────────────── */

static void test_sock_cloexec(void) {
    printf("\n[test_sock_cloexec]\n");

    int s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    CHECK("socket(AF_UNIX, SOCK_CLOEXEC)", s >= 0);
    if (s >= 0) {
        int flags = fcntl(s, F_GETFD);
        CHECK("FD_CLOEXEC set after SOCK_CLOEXEC",
              flags >= 0 && (flags & FD_CLOEXEC) != 0);
        close(s);
    }

    int s_plain = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK("socket(AF_UNIX) without SOCK_CLOEXEC", s_plain >= 0);
    if (s_plain >= 0) {
        int flags = fcntl(s_plain, F_GETFD);
        CHECK("FD_CLOEXEC NOT set without SOCK_CLOEXEC",
              flags >= 0 && (flags & FD_CLOEXEC) == 0);
        close(s_plain);
    }

    int sv[2];
    int rc = socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv);
    CHECK("socketpair(SOCK_CLOEXEC)", rc == 0);
    if (rc == 0) {
        int f0 = fcntl(sv[0], F_GETFD);
        int f1 = fcntl(sv[1], F_GETFD);
        CHECK("socketpair[0] FD_CLOEXEC", f0 >= 0 && (f0 & FD_CLOEXEC));
        CHECK("socketpair[1] FD_CLOEXEC", f1 >= 0 && (f1 & FD_CLOEXEC));
        close(sv[0]); close(sv[1]);
    }
}

/* ── Test: poll on IPC pipe ───────────────────────────────────────── */

static void test_poll_pipe(void) {
    printf("\n[test_poll_pipe]\n");

    int p[2];
    if (pipe(p) != 0) { printf("  FAIL: pipe()\n"); tests_run++; return; }

    char b = 'X';
    CHECK("write 1 byte to pipe", write(p[1], &b, 1) == 1);

    struct pollfd pfd = { .fd = p[0], .events = POLLIN, .revents = 0 };
    int rc = poll(&pfd, 1, 500);
    CHECK("poll returns >= 1 on pipe with data", rc >= 1);
    CHECK("POLLIN set on pipe with data", (pfd.revents & POLLIN) != 0);

    close(p[0]); close(p[1]);
}

/* ── Test: poll on mixed IPC pipe + kernel fd ─────────────────────── */
/* Exercises the optimized forward path (this_cage pollfd pointer). */

static void test_poll_mixed_fds(void) {
    printf("\n[test_poll_mixed_fds]\n");

    int p[2];
    if (pipe(p) != 0) { printf("  FAIL: pipe()\n"); tests_run++; return; }

    const char *path = "poll_mixed_test.tmp";
    int kfd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0644);
    CHECK("open temp kernel fd", kfd >= 0);
    if (kfd < 0) { close(p[0]); close(p[1]); return; }
    /* Regular files are always read-ready, so kfd should report POLLIN. */

    char b = 'Y';
    CHECK("write to pipe write-end", write(p[1], &b, 1) == 1);

    struct pollfd pfds[2] = {
        { .fd = p[0], .events = POLLIN, .revents = 0 },
        { .fd = kfd,  .events = POLLIN, .revents = 0 },
    };
    int rc = poll(pfds, 2, 500);
    CHECK("poll returns >= 2 (both ready)", rc >= 2);
    CHECK("IPC pipe POLLIN", (pfds[0].revents & POLLIN) != 0);
    CHECK("kernel fd POLLIN", (pfds[1].revents & POLLIN) != 0);

    close(p[0]); close(p[1]); close(kfd);
    unlink(path);
}

/* ── Test: ppoll on IPC pipe ──────────────────────────────────────── */

static void test_ppoll_pipe(void) {
    printf("\n[test_ppoll_pipe]\n");

    int p[2];
    if (pipe(p) != 0) { printf("  FAIL: pipe()\n"); tests_run++; return; }

    char b = 'Z';
    CHECK("write 1 byte for ppoll", write(p[1], &b, 1) == 1);

    struct pollfd pfd = { .fd = p[0], .events = POLLIN, .revents = 0 };
    struct timespec to = { .tv_sec = 0, .tv_nsec = 500 * 1000 * 1000 };
    int rc = ppoll(&pfd, 1, &to, NULL);
    CHECK("ppoll returns >= 1 on pipe with data", rc >= 1);
    CHECK("ppoll POLLIN set", (pfd.revents & POLLIN) != 0);

    close(p[0]); close(p[1]);
}

/* ── Test: select on IPC pipe ─────────────────────────────────────── */

static void test_select_pipe(void) {
    printf("\n[test_select_pipe]\n");

    int p[2];
    if (pipe(p) != 0) { printf("  FAIL: pipe()\n"); tests_run++; return; }

    char b = 'X';
    CHECK("write 1 byte", write(p[1], &b, 1) == 1);

    fd_set rfds; FD_ZERO(&rfds); FD_SET(p[0], &rfds);
    struct timeval tv = { .tv_sec = 0, .tv_usec = 500 * 1000 };
    int rc = select(p[0] + 1, &rfds, NULL, NULL, &tv);
    CHECK("select returns >= 1", rc >= 1);
    CHECK("read-end set in fd_set", FD_ISSET(p[0], &rfds));

    char rb = 0;
    CHECK("read drains the byte", read(p[0], &rb, 1) == 1 && rb == 'X');

    close(p[0]); close(p[1]);
}

/* ── Test: select on mixed IPC pipe + kernel fd ───────────────────── */
/* Exercises the optimized this_cage fd_set pointer path. */

static void test_select_mixed_fds(void) {
    printf("\n[test_select_mixed_fds]\n");

    int p[2];
    if (pipe(p) != 0) { printf("  FAIL: pipe()\n"); tests_run++; return; }

    const char *path = "select_mixed_test.tmp";
    int kfd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0644);
    CHECK("open temp kernel fd for select", kfd >= 0);
    if (kfd < 0) { close(p[0]); close(p[1]); return; }

    char b = 'M';
    CHECK("write to pipe", write(p[1], &b, 1) == 1);

    int max = (p[0] > kfd ? p[0] : kfd) + 1;
    fd_set rfds; FD_ZERO(&rfds);
    FD_SET(p[0], &rfds);
    FD_SET(kfd,  &rfds);
    struct timeval tv = { .tv_sec = 0, .tv_usec = 500 * 1000 };
    int rc = select(max, &rfds, NULL, NULL, &tv);
    CHECK("select returns >= 2 (both ready)", rc >= 2);
    CHECK("IPC pipe in fd_set", FD_ISSET(p[0], &rfds));
    CHECK("kernel fd in fd_set", FD_ISSET(kfd, &rfds));

    close(p[0]); close(p[1]); close(kfd);
    unlink(path);
}

/* ── Test: epoll on IPC pipe ──────────────────────────────────────── */

static void test_epoll_pipe(void) {
    printf("\n[test_epoll_pipe]\n");

    int p[2];
    if (pipe(p) != 0) { printf("  FAIL: pipe()\n"); tests_run++; return; }

    int epfd = epoll_create1(0);
    CHECK("epoll_create1", epfd >= 0);
    if (epfd < 0) { close(p[0]); close(p[1]); return; }

    struct epoll_event ev = { .events = EPOLLIN, .data.fd = p[0] };
    CHECK("epoll_ctl ADD on IPC pipe read-end",
          epoll_ctl(epfd, EPOLL_CTL_ADD, p[0], &ev) == 0);

    char b = 'E';
    CHECK("write to pipe for epoll", write(p[1], &b, 1) == 1);

    struct epoll_event events[4] = {0};
    int rc = epoll_wait(epfd, events, 4, 500);
    CHECK("epoll_wait returns >= 1", rc >= 1);
    CHECK("event has EPOLLIN", rc >= 1 && (events[0].events & EPOLLIN) != 0);
    CHECK("event data carries fd", rc >= 1 && events[0].data.fd == p[0]);

    close(epfd); close(p[0]); close(p[1]);
}

/* No test for mixed IPC + kernel fd in epoll: Lind doesn't implement
   eventfd/timerfd/signalfd/inotify, the IPC grate intercepts pipe and
   socket, and regular files aren't epoll-able (Linux returns EPERM).
   That leaves no available kernel fd to exercise the optimized
   epoll_wait forward path with this_cage-tagged kernel_buf. */

/* ── Test: epoll EPOLL_CTL_DEL ────────────────────────────────────── */

static void test_epoll_ctl_del(void) {
    printf("\n[test_epoll_ctl_del]\n");

    int p[2];
    if (pipe(p) != 0) { printf("  FAIL: pipe()\n"); tests_run++; return; }

    int epfd = epoll_create1(0);
    CHECK("epoll_create1 for DEL test", epfd >= 0);
    if (epfd < 0) { close(p[0]); close(p[1]); return; }

    struct epoll_event ev = { .events = EPOLLIN, .data.fd = p[0] };
    CHECK("ADD then DEL — ADD",
          epoll_ctl(epfd, EPOLL_CTL_ADD, p[0], &ev) == 0);
    CHECK("ADD then DEL — DEL",
          epoll_ctl(epfd, EPOLL_CTL_DEL, p[0], NULL) == 0);

    /* Put data in the pipe; epoll_wait should NOT report it (we just removed it). */
    char b = 'D';
    CHECK("write to pipe after DEL", write(p[1], &b, 1) == 1);

    struct epoll_event events[4] = {0};
    int rc = epoll_wait(epfd, events, 4, 100);
    CHECK("epoll_wait returns 0 after DEL (no events)", rc == 0);

    close(epfd); close(p[0]); close(p[1]);
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
    test_popen_exec();
    test_file_io_basic();
    test_fd_collision_after_exec();
    test_large_pipe_correctness();

    /* fcntl / cloexec regression coverage */
    test_fcntl_setfl_preservation();
    test_fcntl_dupfd();
    test_sock_cloexec();

    /* poll / select / ppoll — IPC and mixed-fd coverage */
    test_poll_pipe();
    test_poll_mixed_fds();
    test_ppoll_pipe();
    test_select_pipe();
    test_select_mixed_fds();

    /* epoll — IPC pipe and CTL_DEL */
    test_epoll_pipe();
    test_epoll_ctl_del();

    printf("\n=== results: %d/%d passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
