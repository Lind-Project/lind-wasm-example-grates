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

static int open_for_errno(const char *path) {
    errno = 0;
    return open(path, O_CREAT | O_RDWR, 0644);
}

int main(void) {
    printf("=== fs-routing nested clamp test ===\n");

    CHECK("outer /tmp route returns errno 167",
          open_for_errno("/tmp/noninner") == -1 && errno == 167);

    CHECK("inner /tmp/inner route returns errno 166",
          open_for_errno("/tmp/inner") == -1 && errno == 166);

    int fd = open_for_errno("/dev/null");
    CHECK("unmatched path passes through", fd >= 0);
    if (fd >= 0)
        close(fd);

    printf("\n=== results: %d/%d passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
