#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int tests_run = 0;
static int tests_passed = 0;

#define CHECK(desc, cond)                                                      \
    do {                                                                       \
        tests_run++;                                                           \
        if (cond) {                                                            \
            printf("  PASS: %s\n", desc);                                      \
            tests_passed++;                                                    \
        } else {                                                               \
            printf("  FAIL: %s (errno=%d: %s)\n", desc, errno, strerror(errno)); \
        }                                                                      \
    } while (0)

int main(void) {
    char buf[8] = {0};

    printf("=== fs-routing fcntl dup minimal test ===\n");

    int fd = open("/dev/null", O_WRONLY);
    CHECK("open /dev/null", fd >= 0);
    if (fd < 0)
        return 1;

    errno = 0;
    CHECK("fcntl F_SETFD returns 0", fcntl(fd, F_SETFD, FD_CLOEXEC) == 0);
    CHECK("fcntl F_GETFD sees FD_CLOEXEC", (fcntl(fd, F_GETFD) & FD_CLOEXEC) != 0);

    errno = 0;
    int dup_fd = fcntl(fd, F_DUPFD, 40);
    CHECK("fcntl F_DUPFD returns fd >= minfd", dup_fd >= 40);
    if (dup_fd >= 0)
        CHECK("write through F_DUPFD fd", write(dup_fd, "x", 1) == 1);

    int read_fd = open("/dev/zero", O_RDONLY);
    CHECK("open /dev/zero", read_fd >= 0);
    if (read_fd >= 0) {
        int read_dup = fcntl(read_fd, F_DUPFD, 50);
        CHECK("fcntl F_DUPFD read fd returns fd >= minfd", read_dup >= 50);
        if (read_dup >= 0)
            CHECK("read through F_DUPFD fd", read(read_dup, buf, sizeof(buf)) == (ssize_t)sizeof(buf));
        if (read_dup >= 0)
            close(read_dup);
        close(read_fd);
    }

    if (dup_fd >= 0)
        close(dup_fd);
    close(fd);

    printf("\n=== results: %d/%d passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
