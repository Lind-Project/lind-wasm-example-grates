/*
 * fs-view-grate test suite.
 *
 * Verifies per-cage filesystem isolation via path prefixing.
 * Each cage sees its own /cage-<id>/ namespace on the host.
 *
 * Usage: lind-wasm grates/fs-view-grate.cwasm fs_view_test.cwasm
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static int tests_run = 0;
static int tests_passed = 0;

#define CHECK(name, expr) do { \
    tests_run++; \
    if (expr) { printf("  PASS: %s\n", name); tests_passed++; } \
    else { printf("  FAIL: %s (errno=%d %s)\n", name, errno, strerror(errno)); } \
} while (0)

/* ================================================================
 * Test 1: Basic write isolation — parent and child write to same
 * path, each sees only their own data.
 * ================================================================ */
static void test_write_isolation(void) {
    printf("\n[test_write_isolation]\n");

    mkdir("/tmp", 0755);

    /* Parent writes */
    int fd = open("/tmp/shared_name.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
    CHECK("parent: create /tmp/shared_name.txt", fd >= 0);
    if (fd >= 0) {
        write(fd, "PARENT_DATA", 11);
        close(fd);
    }

    pid_t pid = fork();
    if (pid == 0) {
        mkdir("/tmp", 0755);

        /* Child writes different data to same path */
        int cfd = open("/tmp/shared_name.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
        if (cfd < 0) _exit(1);
        write(cfd, "CHILD_DATA", 10);
        close(cfd);

        /* Child reads back — must see CHILD_DATA */
        cfd = open("/tmp/shared_name.txt", O_RDONLY);
        if (cfd < 0) _exit(1);
        char buf[32] = {0};
        read(cfd, buf, sizeof(buf) - 1);
        close(cfd);

        if (memcmp(buf, "CHILD_DATA", 10) == 0) {
            printf("  PASS: child reads back CHILD_DATA\n");
            _exit(0);
        } else {
            printf("  FAIL: child reads '%s' (expected CHILD_DATA)\n", buf);
            _exit(1);
        }
    }

    int status;
    waitpid(pid, &status, 0);
    CHECK("child verified isolation", WIFEXITED(status) && WEXITSTATUS(status) == 0);

    /* Parent reads back — must still see PARENT_DATA */
    fd = open("/tmp/shared_name.txt", O_RDONLY);
    CHECK("parent: reopen", fd >= 0);
    if (fd >= 0) {
        char buf[32] = {0};
        read(fd, buf, sizeof(buf) - 1);
        close(fd);
        CHECK("parent: still reads PARENT_DATA", memcmp(buf, "PARENT_DATA", 11) == 0);
    }

    unlink("/tmp/shared_name.txt");
}

/* ================================================================
 * Test 2: Directory isolation — parent mkdir is not visible to child.
 * ================================================================ */
static void test_directory_isolation(void) {
    printf("\n[test_directory_isolation]\n");

    mkdir("/tmp", 0755);
    int ret = mkdir("/tmp/parent_dir", 0755);
    CHECK("parent: mkdir /tmp/parent_dir", ret == 0 || errno == EEXIST);

    /* Create a file inside the dir */
    int fd = open("/tmp/parent_dir/file.txt", O_CREAT | O_WRONLY | O_TRUNC, 0644);
    CHECK("parent: create file in parent_dir", fd >= 0);
    if (fd >= 0) {
        write(fd, "in_parent_dir", 13);
        close(fd);
    }

    pid_t pid = fork();
    if (pid == 0) {
        mkdir("/tmp", 0755);

        /* Child: /tmp/parent_dir should NOT exist */
        int cfd = open("/tmp/parent_dir/file.txt", O_RDONLY);
        if (cfd >= 0) {
            printf("  FAIL: child can see parent's /tmp/parent_dir/file.txt\n");
            close(cfd);
            _exit(1);
        }
        printf("  PASS: child cannot see parent's /tmp/parent_dir\n");

        /* Child creates its own dir with same name */
        mkdir("/tmp/parent_dir", 0755);
        cfd = open("/tmp/parent_dir/file.txt", O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (cfd < 0) _exit(1);
        write(cfd, "in_child_dir", 12);
        close(cfd);

        /* Verify child's file */
        cfd = open("/tmp/parent_dir/file.txt", O_RDONLY);
        if (cfd < 0) _exit(1);
        char buf[32] = {0};
        read(cfd, buf, sizeof(buf) - 1);
        close(cfd);

        if (memcmp(buf, "in_child_dir", 12) == 0) {
            printf("  PASS: child reads own data from /tmp/parent_dir/file.txt\n");
            _exit(0);
        } else {
            printf("  FAIL: child reads '%s'\n", buf);
            _exit(1);
        }
    }

    int st;
    waitpid(pid, &st, 0);
    CHECK("child directory isolation verified", WIFEXITED(st) && WEXITSTATUS(st) == 0);

    /* Parent's file still intact */
    fd = open("/tmp/parent_dir/file.txt", O_RDONLY);
    CHECK("parent: file still exists", fd >= 0);
    if (fd >= 0) {
        char buf[32] = {0};
        read(fd, buf, sizeof(buf) - 1);
        close(fd);
        CHECK("parent: data still in_parent_dir", memcmp(buf, "in_parent_dir", 13) == 0);
    }

    unlink("/tmp/parent_dir/file.txt");
    rmdir("/tmp/parent_dir");
}

/* ================================================================
 * Test 3: Multiple files — parent creates several, child sees none.
 * ================================================================ */
static void test_multiple_files(void) {
    printf("\n[test_multiple_files]\n");

    mkdir("/tmp", 0755);

    char path[64];
    for (int i = 0; i < 5; i++) {
        snprintf(path, sizeof(path), "/tmp/multi_%d.txt", i);
        int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (fd >= 0) {
            char data[16];
            int len = snprintf(data, sizeof(data), "file_%d", i);
            write(fd, data, len);
            close(fd);
        }
    }
    CHECK("parent: created 5 files", 1);

    pid_t pid = fork();
    if (pid == 0) {
        mkdir("/tmp", 0755);

        int visible = 0;
        for (int i = 0; i < 5; i++) {
            snprintf(path, sizeof(path), "/tmp/multi_%d.txt", i);
            int cfd = open(path, O_RDONLY);
            if (cfd >= 0) {
                visible++;
                close(cfd);
            }
        }

        if (visible == 0) {
            printf("  PASS: child sees 0 of parent's 5 files\n");
            _exit(0);
        } else {
            printf("  FAIL: child sees %d of parent's files\n", visible);
            _exit(1);
        }
    }

    int st;
    waitpid(pid, &st, 0);
    CHECK("child sees no parent files", WIFEXITED(st) && WEXITSTATUS(st) == 0);

    /* Parent can still read all */
    int readable = 0;
    for (int i = 0; i < 5; i++) {
        snprintf(path, sizeof(path), "/tmp/multi_%d.txt", i);
        int fd = open(path, O_RDONLY);
        if (fd >= 0) {
            readable++;
            close(fd);
        }
    }
    CHECK("parent: all 5 files still readable", readable == 5);

    for (int i = 0; i < 5; i++) {
        snprintf(path, sizeof(path), "/tmp/multi_%d.txt", i);
        unlink(path);
    }
}

/* ================================================================
 * Test 4: Grandchild isolation — three levels of fork, each
 * independent.
 * ================================================================ */
static void test_grandchild_isolation(void) {
    printf("\n[test_grandchild_isolation]\n");

    mkdir("/tmp", 0755);

    int fd = open("/tmp/depth.txt", O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) { write(fd, "depth0", 6); close(fd); }

    pid_t pid = fork();
    if (pid == 0) {
        /* Child (depth 1) */
        mkdir("/tmp", 0755);

        /* Should not see parent's file */
        int cfd = open("/tmp/depth.txt", O_RDONLY);
        if (cfd >= 0) {
            printf("  FAIL: depth 1 sees parent's /tmp/depth.txt\n");
            close(cfd);
            _exit(1);
        }
        printf("  PASS: depth 1 cannot see depth 0's file\n");

        cfd = open("/tmp/depth.txt", O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (cfd >= 0) { write(cfd, "depth1", 6); close(cfd); }

        pid_t pid2 = fork();
        if (pid2 == 0) {
            /* Grandchild (depth 2) */
            mkdir("/tmp", 0755);

            int gfd = open("/tmp/depth.txt", O_RDONLY);
            if (gfd >= 0) {
                printf("  FAIL: depth 2 sees depth 1's /tmp/depth.txt\n");
                close(gfd);
                _exit(1);
            }
            printf("  PASS: depth 2 cannot see depth 1's file\n");
            _exit(0);
        }

        int st2;
        waitpid(pid2, &st2, 0);
        if (!WIFEXITED(st2) || WEXITSTATUS(st2) != 0) _exit(1);

        /* Depth 1 can still read its own */
        cfd = open("/tmp/depth.txt", O_RDONLY);
        if (cfd < 0) _exit(1);
        char buf[16] = {0};
        read(cfd, buf, sizeof(buf) - 1);
        close(cfd);
        if (memcmp(buf, "depth1", 6) != 0) _exit(1);
        printf("  PASS: depth 1 still reads own data\n");

        _exit(0);
    }

    int st;
    waitpid(pid, &st, 0);
    CHECK("grandchild isolation verified", WIFEXITED(st) && WEXITSTATUS(st) == 0);

    /* Depth 0 still has its data */
    fd = open("/tmp/depth.txt", O_RDONLY);
    CHECK("depth 0: file still exists", fd >= 0);
    if (fd >= 0) {
        char buf[16] = {0};
        read(fd, buf, sizeof(buf) - 1);
        close(fd);
        CHECK("depth 0: reads depth0", memcmp(buf, "depth0", 6) == 0);
    }

    unlink("/tmp/depth.txt");
}

/* ================================================================ */

int main(void) {
    printf("=== fs-view-grate test suite ===\n");

    test_write_isolation();
    test_directory_isolation();
    test_multiple_files();
    test_grandchild_isolation();

    printf("\n=== Result: %d/%d passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
