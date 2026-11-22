/* user-view-grate, run as root, who has /uvg_shadow raw.
 *
 * Runs after uvg_shadow_test.c: everything alice did went into her line and nowhere else. */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define SHADOW "/uvg_shadow"
#define EXPECTED                                        \
  "root:$6$rootsalt$roothash:19000:0:99999:7:::\n"      \
  "alice:$6$final$hash:20001:0:99999:7:::\n"            \
  "bob:$6$bobsalt$bobhash:19600:0:99999:7:::\n"

static int failures;

#define CHECK(name, cond)                                   \
  do {                                                      \
    if (cond) {                                             \
      printf("PASS: %s\n", name);                           \
    } else {                                                \
      printf("FAIL: %s (errno=%d)\n", name, errno);         \
      failures++;                                           \
    }                                                       \
  } while (0)

int main(void) {
  char buf[2048];
  size_t n = 0;
  ssize_t r;
  int fd;

  fd = open(SHADOW, O_RDONLY);
  CHECK("root opens the real file", fd >= 0);
  while (n < sizeof(buf) - 1 && (r = read(fd, buf + n, sizeof(buf) - 1 - n)) > 0)
    n += (size_t)r;
  buf[n] = '\0';
  close(fd);
  if (strcmp(buf, EXPECTED) != 0)
    printf("real file is:\n%s", buf);
  CHECK("alice's line changed in place, the others not at all", strcmp(buf, EXPECTED) == 0);

  /* Raw access is the file itself: read-write opens work and nothing is merged or refused. */
  fd = open(SHADOW, O_RDWR);
  CHECK("root opens it read-write", fd >= 0);
  CHECK("root's close", close(fd) == 0);

  printf("%s: %d failure(s)\n", failures ? "FAILED" : "OK", failures);
  return failures ? 1 : 0;
}
