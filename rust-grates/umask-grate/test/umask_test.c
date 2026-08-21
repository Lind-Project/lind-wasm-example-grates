#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <lind_syscall.h>

extern uint64_t __lind_cageid;

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

static mode_t grate_umask(mode_t mask) {
    uint64_t cage = __lind_cageid;
    return (mode_t)make_threei_call(
        95, 0, cage, cage,
        (uint64_t)mask, cage,
        0, cage,
        0, cage,
        0, cage,
        0, cage,
        0, cage,
        0);
}

int main(void) {
    // The grate is launched with --force-bits 022.
    // Any umask the cage sets is OR'd with 0022 and stored inside the grate,
    // so group-write and other-write are always masked out regardless of
    // what the cage requests.

    const char *path = "umask_grate_test_file";
    unlink(path);

    // Test 1: cage requests umask 0000 (no bits masked).
    // Grate forces 0022, so effective umask is 0022.
    // A file created with mode 0666 should land at 0644.
    grate_umask(0000);
    int fd = open(path, O_CREAT | O_RDWR, 0666);
    CHECK("open with umask 0000 (grate forces 0022): file created", fd >= 0);
    if (fd >= 0) {
        CHECK("umask 0000 + force 0022: file mode is 0644", get_file_mode(path) == 0644);
        close(fd);
        unlink(path);
    }

    // Test 2: cage requests umask 0022 (already includes forced bits).
    // Grate OR's 0022 — no change. File with mode 0666 → 0644.
    grate_umask(0022);
    fd = open(path, O_CREAT | O_RDWR, 0666);
    CHECK("open with umask 0022 (matches forced bits): file created", fd >= 0);
    if (fd >= 0) {
        CHECK("umask 0022 + force 0022: file mode is 0644", get_file_mode(path) == 0644);
        close(fd);
        unlink(path);
    }

    // Test 3: cage requests umask 0077 (more restrictive than forced bits).
    // Grate OR's 0022 into 0077 → 0077. File with mode 0666 → 0600.
    grate_umask(0077);
    fd = open(path, O_CREAT | O_RDWR, 0666);
    CHECK("open with umask 0077 (more restrictive): file created", fd >= 0);
    if (fd >= 0) {
        CHECK("umask 0077 + force 0022: file mode is 0600", get_file_mode(path) == 0600);
        close(fd);
        unlink(path);
    }

    // Test 4: cage requests umask 0002 (only other-write masked).
    // Grate OR's 0022 → 0022. File with mode 0666 → 0644.
    grate_umask(0002);
    fd = open(path, O_CREAT | O_RDWR, 0666);
    CHECK("open with umask 0002 (grate adds group-write bit): file created", fd >= 0);
    if (fd >= 0) {
        CHECK("umask 0002 + force 0022: file mode is 0644", get_file_mode(path) == 0644);
        close(fd);
        unlink(path);
    }

    // Test 5: cage requests umask 0777 (maximum restriction).
    // Grate OR's 0022 → 0777. File with mode 0666 → 0000.
    grate_umask(0777);
    fd = open(path, O_CREAT | O_RDWR, 0666);
    CHECK("open with umask 0777 (maximum restriction): file created", fd >= 0);
    if (fd >= 0) {
        CHECK("umask 0777 + force 0022: file mode is 0000", get_file_mode(path) == 0000);
        close(fd);
        unlink(path);
    }

    printf("Result (%d/%d passed).\n", total - failures, total);
    return failures ? 1 : 0;
}
