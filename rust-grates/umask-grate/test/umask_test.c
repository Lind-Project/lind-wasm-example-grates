#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
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

static mode_t get_file_mode(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return (mode_t)-1;
    return st.st_mode & 07777;
}

int main(void) {
    // The grate is launched with --force-bits 022.
    // Any umask the cage sets is OR'd with 0022 before Lind stores it, so
    // group-write and other-write are always masked out regardless of what
    // the cage requests.

    const char *file_path = "umask_grate_test_file";
    const char *dir_path = "umask_grate_test_dir";
    const char *openat_path = "umask_grate_test_dir/openat_file";
    const char *restricted_path = "umask_grate_restricted_file";
    const char *requested_0002_path = "umask_grate_0002_file";
    unlink(file_path);
    unlink(openat_path);
    rmdir(dir_path);
    unlink(restricted_path);
    unlink(requested_0002_path);

    // Test 1: the libc umask() call must route through the grate. Lind then
    // applies the resulting 0022 mask to each normal creation syscall.
    umask(0000);
    CHECK("umask returns the previous enforced mask", umask(0000) == 0022);
    int fd = open(file_path, O_CREAT | O_RDWR, 0666);
    CHECK("open with umask 0000 (grate forces 0022): file created", fd >= 0);
    if (fd >= 0) {
        CHECK("umask 0000 + force 0022: open file mode is 0644", get_file_mode(file_path) == 0644);
        close(fd);
    }

    CHECK("mkdir with umask 0000: directory created", mkdir(dir_path, 0777) == 0);
    CHECK("umask 0000 + force 0022: directory mode is 0755", get_file_mode(dir_path) == 0755);

    int dirfd = open(dir_path, O_RDONLY);
    CHECK("open directory for openat", dirfd >= 0);
    if (dirfd >= 0) {
        fd = openat(dirfd, "openat_file", O_CREAT | O_RDWR, 0666);
        CHECK("openat with umask 0000: file created", fd >= 0);
        if (fd >= 0) {
            CHECK("umask 0000 + force 0022: openat file mode is 0644", get_file_mode(openat_path) == 0644);
            close(fd);
        }
        close(dirfd);
    }

    // Test 2: a more restrictive application mask remains restrictive.
    CHECK("umask 0077 returns the prior mask", umask(0077) == 0022);
    fd = open(restricted_path, O_CREAT | O_RDWR, 0666);
    CHECK("open with umask 0077 (more restrictive): file created", fd >= 0);
    if (fd >= 0) {
        CHECK("umask 0077 + force 0022: file mode is 0600", get_file_mode(restricted_path) == 0600);
        close(fd);
    }

    // Test 3: forced bits tighten a less restrictive application request.
    CHECK("umask 0002 returns the prior mask", umask(0002) == 0077);
    fd = open(requested_0002_path, O_CREAT | O_RDWR, 0666);
    CHECK("open with umask 0002 (grate adds group-write bit): file created", fd >= 0);
    if (fd >= 0) {
        CHECK("umask 0002 + force 0022: file mode is 0644", get_file_mode(requested_0002_path) == 0644);
        close(fd);
    }

    unlink(file_path);
    unlink(openat_path);
    rmdir(dir_path);
    unlink(restricted_path);
    unlink(requested_0002_path);

    printf("Result (%d/%d passed).\n", total - failures, total);
    return failures ? 1 : 0;
}
