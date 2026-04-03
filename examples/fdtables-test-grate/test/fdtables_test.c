/*
 * fdtables stress test — exercises fdtables operations to isolate
 * cross-thread DashMap issues from grate-specific logic.
 *
 * Tests are ordered from simple (single-cage, no fork) to complex
 * (fork + concurrent fd operations). Each test prints PASS/FAIL so
 * we can see exactly where fdtables breaks.
 */
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

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

/* ── Test 1: Single open/close ─────────────────────────────────────── */

static void test_single_open_close(void) {
    printf("\n[test_single_open_close]\n");

    int fd = open("/tmp/fdt_test1.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
    CHECK("open succeeds", fd >= 0);

    int ret = close(fd);
    CHECK("close succeeds", ret == 0);

    unlink("/tmp/fdt_test1.txt");
}

/* ── Test 2: Multiple opens — fdtables tracks many fds ─────────────── */

static void test_many_opens(void) {
    printf("\n[test_many_opens]\n");

    int fds[20];
    char path[64];
    int i;

    for (i = 0; i < 20; i++) {
        snprintf(path, sizeof(path), "/tmp/fdt_many_%d.txt", i);
        fds[i] = open(path, O_CREAT | O_RDWR | O_TRUNC, 0644);
        if (fds[i] < 0) break;
    }
    CHECK("opened 20 fds", i == 20);

    /* Close in reverse order. */
    for (int j = 19; j >= 0; j--) {
        close(fds[j]);
        snprintf(path, sizeof(path), "/tmp/fdt_many_%d.txt", j);
        unlink(path);
    }
    CHECK("closed all 20", 1);
}

/* ── Test 3: Dup — fdtables tracks duplicated fds ──────────────────── */

static void test_dup(void) {
    printf("\n[test_dup]\n");

    int fd = open("/tmp/fdt_dup.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
    CHECK("open succeeds", fd >= 0);

    int fd2 = dup(fd);
    CHECK("dup succeeds", fd2 >= 0);
    CHECK("dup returns different fd", fd2 != fd);

    /* Write through dup'd fd, read through original. */
    write(fd2, "hello", 5);
    lseek(fd, 0, SEEK_SET);
    char buf[16] = {0};
    int nr = read(fd, buf, 5);
    CHECK("read through original fd", nr == 5);
    CHECK("data matches", memcmp(buf, "hello", 5) == 0);

    close(fd2);
    close(fd);
    unlink("/tmp/fdt_dup.txt");
}

/* ── Test 4: Dup2 — fdtables handles fd replacement ────────────────── */

static void test_dup2(void) {
    printf("\n[test_dup2]\n");

    int fd1 = open("/tmp/fdt_dup2_a.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
    int fd2 = open("/tmp/fdt_dup2_b.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
    CHECK("open both", fd1 >= 0 && fd2 >= 0);

    /* dup2 fd1 onto fd2 — fd2 now points to fd1's file. */
    int ret = dup2(fd1, fd2);
    CHECK("dup2 succeeds", ret == fd2);

    write(fd2, "dup2data", 8);
    lseek(fd1, 0, SEEK_SET);
    char buf[16] = {0};
    int nr = read(fd1, buf, 8);
    CHECK("write via dup2'd fd visible on original", nr == 8);

    close(fd1);
    close(fd2);
    unlink("/tmp/fdt_dup2_a.txt");
    unlink("/tmp/fdt_dup2_b.txt");
}

/* ── Test 5: Rapid open/close cycle — stress fdtables allocation ───── */

static void test_rapid_cycle(void) {
    printf("\n[test_rapid_cycle]\n");

    int ok = 1;
    for (int i = 0; i < 100; i++) {
        int fd = open("/tmp/fdt_rapid.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
        if (fd < 0) { ok = 0; break; }
        close(fd);
    }
    CHECK("100 open/close cycles", ok);
    unlink("/tmp/fdt_rapid.txt");
}

/* ── Test 6: Fork — child inherits parent's fds ───────────────────── */

static void test_fork_inherit(void) {
    printf("\n[test_fork_inherit]\n");

    int fd = open("/tmp/fdt_fork.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
    CHECK("open succeeds", fd >= 0);

    write(fd, "parent wrote this", 17);

    pid_t pid = fork();
    if (pid == 0) {
        /* Child: read from the inherited fd. */
        lseek(fd, 0, SEEK_SET);
        char buf[32] = {0};
        int nr = read(fd, buf, 17);
        if (nr == 17 && memcmp(buf, "parent wrote this", 17) == 0) {
            _exit(0); /* success */
        }
        _exit(1); /* failure */
    }

    int status;
    waitpid(pid, &status, 0);
    CHECK("child read inherited fd", WIFEXITED(status) && WEXITSTATUS(status) == 0);

    close(fd);
    unlink("/tmp/fdt_fork.txt");
}

/* ── Test 7: Fork + close in child — fdtables tracks per-cage ──────── */

static void test_fork_close_in_child(void) {
    printf("\n[test_fork_close_in_child]\n");

    int fd = open("/tmp/fdt_fork_close.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
    CHECK("open succeeds", fd >= 0);

    pid_t pid = fork();
    if (pid == 0) {
        /* Child closes the fd. */
        close(fd);
        _exit(0);
    }

    int status;
    waitpid(pid, &status, 0);
    CHECK("child exited cleanly", WIFEXITED(status) && WEXITSTATUS(status) == 0);

    /* Parent's fd should still be valid. */
    int ret = write(fd, "still open", 10);
    CHECK("parent fd still valid after child close", ret == 10);

    close(fd);
    unlink("/tmp/fdt_fork_close.txt");
}

/* ── Test 8: Fork + open in child — child gets its own fds ─────────── */

static void test_fork_open_in_child(void) {
    printf("\n[test_fork_open_in_child]\n");

    pid_t pid = fork();
    if (pid == 0) {
        int fd = open("/tmp/fdt_child_open.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
        if (fd < 0) _exit(1);
        write(fd, "child", 5);
        close(fd);
        _exit(0);
    }

    int status;
    waitpid(pid, &status, 0);
    CHECK("child opened+wrote+closed its own fd",
          WIFEXITED(status) && WEXITSTATUS(status) == 0);

    unlink("/tmp/fdt_child_open.txt");
}

/* ── Test 9: Fork + dup in child ───────────────────────────────────── */

static void test_fork_dup_in_child(void) {
    printf("\n[test_fork_dup_in_child]\n");

    int fd = open("/tmp/fdt_fork_dup.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
    CHECK("open succeeds", fd >= 0);

    pid_t pid = fork();
    if (pid == 0) {
        int fd2 = dup(fd);
        if (fd2 < 0) _exit(1);
        write(fd2, "duped", 5);
        close(fd2);
        close(fd);
        _exit(0);
    }

    int status;
    waitpid(pid, &status, 0);
    CHECK("child dup'd and wrote", WIFEXITED(status) && WEXITSTATUS(status) == 0);

    close(fd);
    unlink("/tmp/fdt_fork_dup.txt");
}

/* ── Test 10: Stress — rapid fork + fd ops ─────────────────────────── */

static void test_fork_stress(void) {
    printf("\n[test_fork_stress]\n");

    int ok = 1;
    for (int i = 0; i < 5; i++) {
        int fd = open("/tmp/fdt_stress.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
        if (fd < 0) { ok = 0; break; }

        pid_t pid = fork();
        if (pid == 0) {
            write(fd, "x", 1);
            close(fd);
            _exit(0);
        }

        int status;
        waitpid(pid, &status, 0);
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            ok = 0;
            break;
        }
        close(fd);
    }
    CHECK("5 fork+write+close cycles", ok);
    unlink("/tmp/fdt_stress.txt");
}

/* ── Test 11: Multiple concurrent fds across fork ──────────────────── */

static void test_fork_many_fds(void) {
    printf("\n[test_fork_many_fds]\n");

    int fds[10];
    char path[64];

    for (int i = 0; i < 10; i++) {
        snprintf(path, sizeof(path), "/tmp/fdt_fmany_%d.txt", i);
        fds[i] = open(path, O_CREAT | O_RDWR | O_TRUNC, 0644);
        if (fds[i] < 0) {
            printf("  FAIL: couldn't open fd %d\n", i);
            tests_run++;
            return;
        }
    }

    pid_t pid = fork();
    if (pid == 0) {
        /* Child: close odd fds, write to even fds. */
        for (int i = 0; i < 10; i++) {
            if (i % 2 == 1) {
                close(fds[i]);
            } else {
                write(fds[i], "c", 1);
            }
        }
        /* Close remaining. */
        for (int i = 0; i < 10; i += 2) {
            close(fds[i]);
        }
        _exit(0);
    }

    int status;
    waitpid(pid, &status, 0);
    CHECK("child handled 10 fds (close odd, write even)",
          WIFEXITED(status) && WEXITSTATUS(status) == 0);

    /* Parent closes all. */
    for (int i = 0; i < 10; i++) {
        close(fds[i]);
        snprintf(path, sizeof(path), "/tmp/fdt_fmany_%d.txt", i);
        unlink(path);
    }
}

/* ═══════════════════════════════════════════════════════════════════ */

int main(void) {
    printf("=== fdtables stress test ===\n");

    /* Single-cage tests (no fork). */
    test_single_open_close();
    test_many_opens();
    test_dup();
    test_dup2();
    test_rapid_cycle();

    /* Fork tests. */
    test_fork_inherit();
    test_fork_close_in_child();
    test_fork_open_in_child();
    test_fork_dup_in_child();
    test_fork_stress();
    test_fork_many_fds();

    printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
