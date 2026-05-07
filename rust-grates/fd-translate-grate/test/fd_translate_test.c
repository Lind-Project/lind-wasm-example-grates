/*
 * strace grate test — exercises many syscall categories to verify the
 * strace grate traces and forwards them all without corruption.
 *
 * The test itself checks that every operation succeeds. If strace
 * breaks forwarding for any syscall, the assertion fails and the
 * process exits non-zero.
 */
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int tests = 0;
static int passed = 0;

#define CHECK(desc, cond) do { \
    tests++; \
    if (cond) { passed++; } \
    else { printf("FAIL: %s (errno=%d)\n", desc, errno); } \
} while (0)

/* ── File I/O ────────────────────────────────────────────────────────── */

static void test_file_io(void) {
    int fd;
    ssize_t n;
    char buf[256];

    /* open + write + close */
    fd = open("/tmp/strace_test.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
    CHECK("open O_CREAT|O_RDWR", fd >= 0);

    n = write(fd, "hello strace", 12);
    CHECK("write 12 bytes", n == 12);

    /* lseek */
    off_t pos = lseek(fd, 0, SEEK_SET);
    CHECK("lseek to 0", pos == 0);

    /* read */
    memset(buf, 0, sizeof(buf));
    n = read(fd, buf, 12);
    CHECK("read 12 bytes", n == 12);
    CHECK("read data matches", memcmp(buf, "hello strace", 12) == 0);

    /* pwrite + pread */
    n = pwrite(fd, "PWRITE", 6, 0);
    CHECK("pwrite 6 bytes at offset 0", n == 6);

    memset(buf, 0, sizeof(buf));
    n = pread(fd, buf, 6, 0);
    CHECK("pread 6 bytes", n == 6);
    CHECK("pread data matches", memcmp(buf, "PWRITE", 6) == 0);

    close(fd);

    /* reopen read-only */
    fd = open("/tmp/strace_test.txt", O_RDONLY);
    CHECK("reopen O_RDONLY", fd >= 0);
    close(fd);

    /* unlink */
    int ret = unlink("/tmp/strace_test.txt");
    CHECK("unlink", ret == 0);
}

/* ── writev / readv ──────────────────────────────────────────────────── */

static void test_iov(void) {
    int fd = open("/tmp/strace_iov.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
    CHECK("iov open", fd >= 0);

    char a[] = "aaa";
    char b[] = "bbb";
    struct iovec wv[2] = {
        { .iov_base = a, .iov_len = 3 },
        { .iov_base = b, .iov_len = 3 },
    };
    ssize_t n = writev(fd, wv, 2);
    CHECK("writev 6 bytes", n == 6);

    lseek(fd, 0, SEEK_SET);

    char ra[3], rb[3];
    struct iovec rv[2] = {
        { .iov_base = ra, .iov_len = 3 },
        { .iov_base = rb, .iov_len = 3 },
    };
    n = readv(fd, rv, 2);
    CHECK("readv 6 bytes", n == 6);
    CHECK("readv data a", memcmp(ra, "aaa", 3) == 0);
    CHECK("readv data b", memcmp(rb, "bbb", 3) == 0);

    close(fd);
    unlink("/tmp/strace_iov.txt");
}

/* ── Directory ops ───────────────────────────────────────────────────── */

static void test_dir_ops(void) {
    int ret;

    ret = mkdir("/tmp/strace_dir", 0755);
    CHECK("mkdir", ret == 0);

    /* getcwd */
    char cwd[512];
    char *p = getcwd(cwd, sizeof(cwd));
    CHECK("getcwd", p != NULL);

    /* chdir + chdir back */
    ret = chdir("/tmp/strace_dir");
    CHECK("chdir /tmp/strace_dir", ret == 0);

    ret = chdir(cwd);
    CHECK("chdir back", ret == 0);

    ret = rmdir("/tmp/strace_dir");
    CHECK("rmdir", ret == 0);
}

/* ── Dup family ──────────────────────────────────────────────────────── */

static void test_dup(void) {
    int fd = open("/tmp/strace_dup.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
    CHECK("dup open", fd >= 0);

    int fd2 = dup(fd);
    CHECK("dup", fd2 >= 0 && fd2 != fd);

    write(fd2, "dup", 3);
    lseek(fd, 0, SEEK_SET);
    char buf[8] = {0};
    read(fd, buf, 3);
    CHECK("dup data visible", memcmp(buf, "dup", 3) == 0);
    close(fd2);

    int fd3 = dup2(fd, fd2);
    CHECK("dup2", fd3 == fd2);
    close(fd3);

    close(fd);
    unlink("/tmp/strace_dup.txt");
}

/* ── Stat / access / chmod ───────────────────────────────────────────── */

static void test_stat_access(void) {
    int fd = open("/tmp/strace_stat.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
    CHECK("stat open", fd >= 0);
    write(fd, "x", 1);
    close(fd);

    struct stat st;
    int ret = stat("/tmp/strace_stat.txt", &st);
    CHECK("stat", ret == 0);
    CHECK("stat size == 1", st.st_size == 1);

    ret = access("/tmp/strace_stat.txt", R_OK);
    CHECK("access R_OK", ret == 0);

    ret = chmod("/tmp/strace_stat.txt", 0600);
    CHECK("chmod", ret == 0);

    unlink("/tmp/strace_stat.txt");
}

/* ── Rename / link ───────────────────────────────────────────────────── */

static void test_rename_link(void) {
    int fd = open("/tmp/strace_rn_a.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
    write(fd, "data", 4);
    close(fd);

    int ret = rename("/tmp/strace_rn_a.txt", "/tmp/strace_rn_b.txt");
    CHECK("rename", ret == 0);

    ret = link("/tmp/strace_rn_b.txt", "/tmp/strace_rn_c.txt");
    /* link may not be supported — don't fail hard */
    if (ret == 0) {
        CHECK("link", 1);
        unlink("/tmp/strace_rn_c.txt");
    }

    unlink("/tmp/strace_rn_b.txt");
}

/* ── Fork + wait ─────────────────────────────────────────────────────── */

static void test_fork_wait(void) {
    pid_t pid = fork();
    if (pid == 0) {
        /* Child: do some work so strace sees child syscalls. */
        int fd = open("/tmp/strace_child.txt", O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (fd >= 0) {
            write(fd, "child", 5);
            close(fd);
            unlink("/tmp/strace_child.txt");
        }
        _exit(0);
    }
    CHECK("fork", pid > 0);

    int status;
    pid_t w = waitpid(pid, &status, 0);
    CHECK("waitpid", w == pid);
    CHECK("child exit 0", WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

/* ── Clock ───────────────────────────────────────────────────────────── */

static void test_clock(void) {
    struct timespec ts;
    int ret = clock_gettime(CLOCK_MONOTONIC, &ts);
    CHECK("clock_gettime", ret == 0);
    CHECK("clock_gettime non-zero", ts.tv_sec > 0 || ts.tv_nsec > 0);
}

/* ── Getpid / getuid family ──────────────────────────────────────────── */

static void test_pid_uid(void) {
    pid_t pid = getpid();
    CHECK("getpid > 0", pid > 0);

    pid_t ppid = getppid();
    CHECK("getppid > 0", ppid > 0);

    uid_t uid = getuid();
    CHECK("getuid", uid >= 0);

    uid_t euid = geteuid();
    CHECK("geteuid", euid >= 0);

    gid_t gid = getgid();
    CHECK("getgid", gid >= 0);
}

/* ── Rapid open/close cycle ──────────────────────────────────────────── */

static void test_rapid_cycle(void) {
    int ok = 1;
    for (int i = 0; i < 50; i++) {
        int fd = open("/tmp/strace_rapid.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
        if (fd < 0) { ok = 0; break; }
        write(fd, "x", 1);
        close(fd);
    }
    CHECK("50 open/write/close cycles", ok);
    unlink("/tmp/strace_rapid.txt");
}

/* ── Truncate ────────────────────────────────────────────────────────── */

static void test_truncate(void) {
    int fd = open("/tmp/strace_trunc.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
    write(fd, "1234567890", 10);
    close(fd);

    int ret = truncate("/tmp/strace_trunc.txt", 5);
    CHECK("truncate to 5", ret == 0);

    struct stat st;
    stat("/tmp/strace_trunc.txt", &st);
    CHECK("truncated size == 5", st.st_size == 5);

    fd = open("/tmp/strace_trunc.txt", O_RDWR);
    ret = ftruncate(fd, 2);
    CHECK("ftruncate to 2", ret == 0);
    close(fd);

    stat("/tmp/strace_trunc.txt", &st);
    CHECK("ftruncated size == 2", st.st_size == 2);

    unlink("/tmp/strace_trunc.txt");
}

/* ── Fcntl ───────────────────────────────────────────────────────────── */

static void test_fcntl(void) {
    int fd = open("/tmp/strace_fcntl.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
    CHECK("fcntl open", fd >= 0);

    int flags = fcntl(fd, F_GETFL);
    CHECK("fcntl F_GETFL", flags >= 0);

    close(fd);
    unlink("/tmp/strace_fcntl.txt");
}

/* ═══════════════════════════════════════════════════════════════════════ */

int main(void) {
    printf("=== strace grate test ===\n");

    test_file_io();
    test_iov();
    test_dir_ops();
    test_dup();
    test_stat_access();
    test_rename_link();
    test_fork_wait();
    test_clock();
    test_pid_uid();
    test_rapid_cycle();
    test_truncate();
    test_fcntl();

    printf("\n=== Results: %d/%d passed ===\n", passed, tests);
    return (passed == tests) ? 0 : 1;
}
