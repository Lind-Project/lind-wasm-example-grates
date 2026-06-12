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

static mode_t get_mode(int fd) {
    struct stat st;
    if (fstat(fd, &st) != 0) return (mode_t)-1;
    return st.st_mode & 07777;
}

int main(void) {
    // Test file is cleaned up on each run to avoid leftover state.
    const char *path = "fchmod_test_file";
    unlink(path);

    int fd = open(path, O_CREAT | O_RDWR, 0600);
    CHECK("open: create test file", fd >= 0);
    if (fd < 0) goto done;

    // The grate is launched with --mask 644.
    // All modes are ANDed with 0644 before reaching the kernel.

    // Bits above the mask are stripped.
    CHECK("fchmod: 0777 masked to 0644", fchmod(fd, 0777) == 0);
    CHECK("fstat: mode is 0644 after fchmod(0777)", get_mode(fd) == 0644);

    CHECK("fchmod: 0755 masked to 0644", fchmod(fd, 0755) == 0);
    CHECK("fstat: mode is 0644 after fchmod(0755)", get_mode(fd) == 0644);

    // Bits within the mask are preserved.
    CHECK("fchmod: 0600 within mask, unchanged", fchmod(fd, 0600) == 0);
    CHECK("fstat: mode is 0600 after fchmod(0600)", get_mode(fd) == 0600);

    CHECK("fchmod: 0644 equals mask, unchanged", fchmod(fd, 0644) == 0);
    CHECK("fstat: mode is 0644 after fchmod(0644)", get_mode(fd) == 0644);

    // All bits cleared.
    CHECK("fchmod: 0000 stays 0000", fchmod(fd, 0000) == 0);
    CHECK("fstat: mode is 0000 after fchmod(0000)", get_mode(fd) == 0000);

    // setuid bit (04000) is not in mask 0644 and is stripped.
    CHECK("fchmod: setuid bit in 04755 is stripped", fchmod(fd, 04755) == 0);
    CHECK("fstat: mode is 0644 after fchmod(04755)", get_mode(fd) == 0644);

    close(fd);
    unlink(path);

done:
    printf("Result (%d/%d passed).\n", total - failures, total);
    return failures ? 1 : 0;
}
