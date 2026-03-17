#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>

#define TEST_DIR "seccomp_test_dir"

int main() {
    // mkdir whitelisted
    int ret = mkdir(TEST_DIR, 0755);
    assert(ret == 0);

    // rmdir() blacklisted
    ret = rmdir(TEST_DIR);
    assert(ret == -1);
    assert(errno == EPERM);

    printf("PASS\n");
    return 0;
}
