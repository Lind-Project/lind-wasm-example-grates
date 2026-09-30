#include <assert.h>
#include <fcntl.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

static void assert_file_eq(const char *path, const char *expected) {
  char buf[256];
  int fd = open(path, O_RDONLY);
  assert(fd >= 0);
  ssize_t n = read(fd, buf, sizeof(buf) - 1);
  assert(n >= 0);
  buf[n] = '\0';
  close(fd);
  assert(strcmp(buf, expected) == 0);
}

int main(void) {
  int fd = open("redaction_write.txt", O_CREAT | O_TRUNC | O_RDWR, 0666);
  assert(fd >= 0);
  assert(write(fd, "token=secret keep\n", 18) == 18);
  close(fd);
  assert_file_eq("redaction_write.txt", "token=****** keep\n");
  unlink("redaction_write.txt");

  fd = open("redaction_pwrite.txt", O_CREAT | O_TRUNC | O_RDWR, 0666);
  assert(fd >= 0);
  assert(pwrite(fd, "before secret after", 19, 0) == 19);
  close(fd);
  assert_file_eq("redaction_pwrite.txt", "before ****** after");
  unlink("redaction_pwrite.txt");

  fd = open("redaction_writev.txt", O_CREAT | O_TRUNC | O_RDWR, 0666);
  assert(fd >= 0);
  struct iovec iov[3];
  iov[0].iov_base = "split se";
  iov[0].iov_len = 8;
  iov[1].iov_base = "cr";
  iov[1].iov_len = 2;
  iov[2].iov_base = "et done";
  iov[2].iov_len = 7;
  assert(writev(fd, iov, 3) == 17);
  close(fd);
  assert_file_eq("redaction_writev.txt", "split ****** done");
  unlink("redaction_writev.txt");

  return 0;
}
