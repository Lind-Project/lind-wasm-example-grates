#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/uio.h>

int main(void) {
  int fd = open("testfile.txt", O_WRONLY | O_CREAT, 0666);
  assert(fd >= 0);

  // --- write() test ---
  errno = 0;
  ssize_t ret = write(fd, "hello", 5);

  // write() must fail
  assert(ret == EPERM);

  // --- writev() test ---
  struct iovec iov[2];
  iov[0].iov_base = "he";
  iov[0].iov_len  = 2;
  iov[1].iov_base = "llo";
  iov[1].iov_len  = 3;

  errno = 0;
  ret = writev(fd, iov, 2);

  // writev() must fail
  assert(ret == EPERM);

  // --- pwrite() test ---
  errno = 0;
  ret = pwrite(fd, "hello", 5, 0);

  // pwrite() must fail
  assert(ret == EPERM);

  close(fd);

  // remove testfile
  unlink("testfile.txt");

  return 0;
}
