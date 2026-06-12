#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int failures = 0;
static int total = 0;

#define PASS(x) \
    do { printf("PASS: %s\n", x); } while (0)

#define FAIL(x) \
    do { printf("FAIL: %s (%s)\n", x, strerror(errno)); failures++; } while (0)

#define CHECK(x, expr) \
    do { total++; if (expr) PASS(x); else FAIL(x); } while (0)

static mode_t get_mode(int fd) {
    struct stat st;
    if (fstat(fd, &st) != 0) return (mode_t)-1;
    return st.st_mode & 07777;
}

int main(void) {
    const char *path = "fchmodat_test_file";
    unlink(path);

    int fd = open(path, O_CREAT | O_RDWR, 0600);
    CHECK("open: create test file", fd >= 0);
    if (fd < 0) goto done;

    // --- AT_FDCWD, flags=0 ---
    // The grate is launched with --mask 644.
    // All modes are ANDed with 0644 before reaching the kernel.

    // Bits above the mask are stripped.
    CHECK("fchmodat AT_FDCWD: 0777 masked to 0644", fchmodat(AT_FDCWD, path, 0777, 0) == 0);
    CHECK("fstat: mode is 0644 after fchmodat(AT_FDCWD, 0777)", get_mode(fd) == 0644);

    CHECK("fchmodat AT_FDCWD: 0755 masked to 0644", fchmodat(AT_FDCWD, path, 0755, 0) == 0);
    CHECK("fstat: mode is 0644 after fchmodat(AT_FDCWD, 0755)", get_mode(fd) == 0644);

    // Bits within the mask are preserved.
    CHECK("fchmodat AT_FDCWD: 0600 within mask, unchanged", fchmodat(AT_FDCWD, path, 0600, 0) == 0);
    CHECK("fstat: mode is 0600 after fchmodat(AT_FDCWD, 0600)", get_mode(fd) == 0600);

    CHECK("fchmodat AT_FDCWD: 0644 equals mask, unchanged", fchmodat(AT_FDCWD, path, 0644, 0) == 0);
    CHECK("fstat: mode is 0644 after fchmodat(AT_FDCWD, 0644)", get_mode(fd) == 0644);

    // All bits cleared.
    CHECK("fchmodat AT_FDCWD: 0000 stays 0000", fchmodat(AT_FDCWD, path, 0000, 0) == 0);
    CHECK("fstat: mode is 0000 after fchmodat(AT_FDCWD, 0000)", get_mode(fd) == 0000);

    // setuid bit (04000) is not in mask 0644 and is stripped.
    CHECK("fchmodat AT_FDCWD: setuid bit in 04755 is stripped", fchmodat(AT_FDCWD, path, 04755, 0) == 0);
    CHECK("fstat: mode is 0644 after fchmodat(AT_FDCWD, 04755)", get_mode(fd) == 0644);

    // --- Real dirfd, flags=0 ---
    int dirfd = open(".", O_RDONLY | O_DIRECTORY);
    CHECK("open: get dirfd for cwd", dirfd >= 0);
    if (dirfd >= 0) {
        CHECK("fchmodat dirfd: 0777 masked to 0644", fchmodat(dirfd, path, 0777, 0) == 0);
        CHECK("fstat: mode is 0644 after fchmodat(dirfd, 0777)", get_mode(fd) == 0644);

        CHECK("fchmodat dirfd: 0600 within mask, unchanged", fchmodat(dirfd, path, 0600, 0) == 0);
        CHECK("fstat: mode is 0600 after fchmodat(dirfd, 0600)", get_mode(fd) == 0600);

        close(dirfd);
    }

    // --- Absolute path (dirfd is ignored) ---
    char abspath[PATH_MAX];
    if (getcwd(abspath, sizeof(abspath)) != NULL) {
        size_t cwdlen = strlen(abspath);
        abspath[cwdlen] = '/';
        strncpy(abspath + cwdlen + 1, path, PATH_MAX - cwdlen - 2);
        abspath[PATH_MAX - 1] = '\0';

        CHECK("fchmodat absolute: 0777 masked to 0644", fchmodat(AT_FDCWD, abspath, 0777, 0) == 0);
        CHECK("fstat: mode is 0644 after fchmodat(absolute, 0777)", get_mode(fd) == 0644);
    }

    // --- AT_SYMLINK_NOFOLLOW ---
    // Linux does not support changing permissions on a symlink itself (ENOTSUP).
    // Verify the grate propagates this kernel error correctly.
    errno = 0;
    CHECK("fchmodat AT_SYMLINK_NOFOLLOW: returns ENOTSUP on Linux",
          fchmodat(AT_FDCWD, path, 0600, AT_SYMLINK_NOFOLLOW) == -1 &&
          (errno == ENOTSUP || errno == EOPNOTSUPP));

    close(fd);
    unlink(path);

done:
    printf("Result (%d/%d passed).\n", total - failures, total);
    return failures ? 1 : 0;
}
