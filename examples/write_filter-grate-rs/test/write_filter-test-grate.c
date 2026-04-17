#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <unistd.h>

int main(void) {
  int fd;
  ssize_t ret;

  // write() test

  /* .log file should succeed */
  fd = open("filetest.log", O_WRONLY | O_CREAT | O_TRUNC, 0666);
  assert(fd >= 0);

  ret = write(fd, "Hello, log!\n", 12);
  assert(ret == 12);
  close(fd);
  unlink("filetest.log");

  /* .txt file should fail on write */
  fd = open("filetest.txt", O_WRONLY | O_CREAT | O_TRUNC, 0666);
  assert(fd >= 0);

  ret = write(fd, "Hello, txt!\n", 11);
  assert(ret == -1 && errno == EPERM);

  close(fd);
  unlink("filetest.txt");

  // pwrite() test

  /* .log file should succeed */
  fd = open("filetest.log", O_WRONLY | O_CREAT | O_TRUNC, 0666);
  assert(fd >= 0);

  ret = pwrite(fd, "Hello, log!\n", 12, 0);
  assert(ret == 12);

  close(fd);
  unlink("filetest.log");

  /* .txt file should fail on pwrite */
  fd = open("filetest.txt", O_WRONLY | O_CREAT | O_TRUNC, 0666);
  assert(fd >= 0);

  ret = pwrite(fd, "Hello, txt!\n", 11, 0);
  assert(ret == -1 && errno == EPERM);

  close(fd);
  unlink("filetest.txt");

  // writev() test

  struct iovec iov[2];

  /* .log file should succeed */
  fd = open("filetest.log", O_WRONLY | O_CREAT | O_TRUNC, 0666);
  assert(fd >= 0);

  iov[0].iov_base = "Hello, ";
  iov[0].iov_len = 7;
  iov[1].iov_base = "log!\n";
  iov[1].iov_len = 5;

  ret = writev(fd, iov, 2);
  assert(ret == 12);

  close(fd);
  unlink("filetest.log");

  /* .txt file should fail on writev */
  fd = open("filetest.txt", O_WRONLY | O_CREAT | O_TRUNC, 0666);
  assert(fd >= 0);

  iov[0].iov_base = "Hello, ";
  iov[0].iov_len = 7;
  iov[1].iov_base = "txt!\n";
  iov[1].iov_len = 5;

  ret = writev(fd, iov, 2);
  assert(ret == -1 && errno == EPERM);

  close(fd);
  unlink("filetest.txt");

  return 0;
}
