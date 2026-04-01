#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

int main(void) {
  int fd;
  ssize_t ret;

  /* .log file should succeed */
  fd = open("filetest.log", O_WRONLY | O_CREAT | O_TRUNC, 0666);
  assert(fd >= 0); // open succeeds

  ret = write(fd, "Hello, log!\n", 12);
  assert(ret == 12); // write succeeds
  close(fd);
  unlink("filetest.log");

  /* .txt file should fail on write */
  fd = open("filetest.txt", O_WRONLY | O_CREAT | O_TRUNC, 0666);
  assert(fd >= 0); // open succeeds

  ret = write(fd, "Hello, txt!\n", 11);
  // errno 63 is mapped to EPERM in wasi
  assert(ret == 63);
  close(fd);
  unlink("filetest.log");

  return 0;
}
