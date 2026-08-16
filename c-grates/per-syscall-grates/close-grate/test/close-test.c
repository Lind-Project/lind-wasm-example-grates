#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>

int main() {
    int fd;
    const char *filename = "testfile.txt";

    // 1. Open a file to get a valid fd
    fd = open(filename, O_CREAT | O_RDWR, 0644);
    assert(fd >= 0);

    // 2. Close should succeed
    int ret = close(fd);
    assert(ret == 0);

    // 3. Closing again should fail (EBADF)
    ret = close(fd);
    assert(ret == -1);
    assert(errno == EBADF);

    // 4. Closing an invalid fd should fail
    ret = close(-1);
    assert(ret == -1);
    assert(errno == EBADF);

    // 5. Cleanup: remove the file
    ret = unlink(filename);
    assert(ret == 0);

    printf("All close() tests passed.\n");
    return 0;
}
