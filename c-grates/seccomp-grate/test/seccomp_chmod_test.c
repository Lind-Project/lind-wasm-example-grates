#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#define TEST_FILE "seccomp_test_file"

int main() {
  int fd = open(TEST_FILE, O_CREAT | O_WRONLY, 0644);
  assert(fd >= 0);
  close(fd);

  int ret = chmod(TEST_FILE, 0777);
  assert(ret == -1);
  assert(errno == EPERM);

  ret = unlink(TEST_FILE);
  assert(ret == 0);

  printf("PASS\n");
  return 0;
}
