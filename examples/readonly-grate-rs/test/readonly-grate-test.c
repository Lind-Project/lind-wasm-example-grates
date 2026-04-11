#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/uio.h>

int main(void) {
  int fd;
  ssize_t ret;

  // --- OPEN TESTS ---

  // O_WRONLY should fail
  errno = 0;
  fd = open("testfile.txt", O_WRONLY | O_CREAT, 0666);
  assert(fd == -1 && errno == EPERM);

  // O_RDWR should fail
  errno = 0;
  fd = open("testfile.txt", O_RDWR | O_CREAT, 0666);
  assert(fd == -1 && errno == EPERM);

  // O_TRUNC should fail
  errno = 0;
  fd = open("testfile.txt", O_RDONLY | O_TRUNC);
  assert(fd == -1 && errno == EPERM);

  // O_APPEND should fail
  errno = 0;
  fd = open("testfile.txt", O_RDONLY | O_APPEND);
  assert(fd == -1 && errno == EPERM);

  // O_RDONLY should succeed
  errno = 0;
  fd = open("testfile.txt", O_RDONLY | O_CREAT, 0666);
  assert(fd >= 0);

  // --- WRITE TESTS ---

  // write()
  errno = 0;
  ret = write(1, "hello", 5);
  assert(ret == -1 && errno == EPERM);

  // writev()
  struct iovec iov[2];
  iov[0].iov_base = "he";
  iov[0].iov_len  = 2;
  iov[1].iov_base = "llo";
  iov[1].iov_len  = 3;

  errno = 0;
  ret = writev(fd, iov, 2);
  assert(ret == -1 && errno == EPERM);

  // pwrite()
  errno = 0;
  ret = pwrite(fd, "hello", 5, 0);
  assert(ret == -1 && errno == EPERM);

  // --- CLEANUP ---
  close(fd);
  unlink("testfile.txt");

  return 0;
}
