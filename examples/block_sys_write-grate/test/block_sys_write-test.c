#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
  int fd = open("testfile.txt", O_WRONLY | O_CREAT, 0666);
  assert(fd >= 0);

  ssize_t ret = write(fd, "hello", 5);

  // write() must fail
  assert(ret == EPERM);
  close(fd);
  
  // remove testfile
  unlink("testfile.txt");
  
  return 0;
}
