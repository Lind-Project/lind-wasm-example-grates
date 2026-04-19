#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int total = 0;
static int failures = 0;

#define CHECK(name, expr) do { \
    total++; \
    if (expr) { printf("PASS: %s\n", name); } \
    else { printf("FAIL: %s (errno=%d)\n", name, errno); failures++; } \
} while (0)

int main(void) {
    int fd;
    ssize_t ret;
    char buf[64];

    /* open /dev/null */
    fd = open("/dev/null", O_RDWR);
    CHECK("open /dev/null", fd >= 0);

    /* write should succeed and return byte count */
    ret = write(fd, "hello", 5);
    CHECK("write returns count", ret == 5);

    /* read should return 0 (EOF) */
    ret = read(fd, buf, sizeof(buf));
    CHECK("read returns 0 (EOF)", ret == 0);

    /* large write */
    char big[4096];
    memset(big, 'X', sizeof(big));
    ret = write(fd, big, sizeof(big));
    CHECK("large write returns count", ret == 4096);

    /* close */
    CHECK("close succeeds", close(fd) == 0);

    /* open a real file still works */
    fd = open("/tmp/devnull_test_real.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
    CHECK("open real file", fd >= 0);
    ret = write(fd, "real data", 9);
    CHECK("write to real file", ret == 9);
    lseek(fd, 0, SEEK_SET);
    memset(buf, 0, sizeof(buf));
    ret = read(fd, buf, sizeof(buf));
    CHECK("read from real file", ret == 9 && memcmp(buf, "real data", 9) == 0);
    close(fd);
    unlink("/tmp/devnull_test_real.txt");

    /* multiple /dev/null fds */
    int fd1 = open("/dev/null", O_WRONLY);
    int fd2 = open("/dev/null", O_RDONLY);
    CHECK("multiple devnull fds", fd1 >= 0 && fd2 >= 0 && fd1 != fd2);
    write(fd1, "a", 1);
    ret = read(fd2, buf, 1);
    CHECK("read from second devnull fd", ret == 0);
    close(fd1);
    close(fd2);

    printf("\nResult: %d/%d passed\n", total - failures, total);
    return failures ? 1 : 0;
}
