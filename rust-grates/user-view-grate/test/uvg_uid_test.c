/* user-view-grate with no --user: the cage is whoever its effective uid says.
 *
 * /uvg_uid shows each uid the lines starting "<uid>:". The fixture has none for the uid this
 * test runs as, so the view starts empty. The test adds a line of its own, cannot add one for
 * another uid, and removes its line again. */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define FILE_PATH "/uvg_uid"

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

static int reads_as(const char *want) {
  char buf[512];
  size_t n = 0;
  ssize_t r;
  int fd = open(FILE_PATH, O_RDONLY);
  if (fd < 0)
    return 0;
  while (n < sizeof(buf) - 1 && (r = read(fd, buf + n, sizeof(buf) - 1 - n)) > 0)
    n += (size_t)r;
  buf[n] = '\0';
  close(fd);
  if (strcmp(buf, want) != 0)
    printf("view is:\n%s", buf);
  return strcmp(buf, want) == 0;
}

/* Append `line` to the view. Returns what close() returned. */
static int append(const char *line) {
  int fd = open(FILE_PATH, O_WRONLY | O_APPEND);
  if (fd < 0)
    return -2;
  if (write(fd, line, strlen(line)) != (ssize_t)strlen(line)) {
    close(fd);
    return -2;
  }
  return close(fd);
}

int main(void) {
  char mine[64], theirs[64];
  unsigned uid = (unsigned)geteuid();
  int fd;

  /* The fixture's lines are for uids 4000001 and 4000002. */
  if (uid == 4000001u || uid == 4000002u) {
    printf("SKIP: running as uid %u, which the fixture uses\n", uid);
    return 0;
  }
  snprintf(mine, sizeof(mine), "%u:written by uid %u\n", uid, uid);
  snprintf(theirs, sizeof(theirs), "%u:not mine\n", uid + 1);

  CHECK("no line for this uid yet", reads_as(""));
  CHECK("add own line", append(mine) == 0);
  CHECK("own line visible", reads_as(mine));

  errno = 0;
  CHECK("line for another uid refused", append(theirs) == -1 && errno == EPERM);
  CHECK("view unchanged", reads_as(mine));

  /* Emptying the view takes this uid's line out of the file again. */
  fd = open(FILE_PATH, O_WRONLY | O_TRUNC);
  CHECK("empty the view", fd >= 0 && close(fd) == 0);
  CHECK("line removed", reads_as(""));

  printf("%s: %d failure(s)\n", failures ? "FAILED" : "OK", failures);
  return failures ? 1 : 0;
}
