/* user-view-grate, run as support: read-only views with lines dropped and fields masked.
 *
 * The expected text is also checked against the same policy and fixtures by the unit test
 * `test_suite_policy_and_fixtures` in src/policy.rs. */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define PAYMENTS                                                                                        \
  "2026-11-20T10:00:01 INFO charge user=alice card=4111-****-****-1111 amount=12.50 token=[redacted]\n" \
  "2026-11-20T10:00:03 INFO refund user=bob card=5500-****-****-0004 amount=3.00 token=[redacted]\n"    \
  "2026-11-20T10:00:04 WARN declined user=carol card=3400-****-****-0009\n"
#define INVOICES "id,-,amount,-\n1001,-,1200.00,-\n1002,-,89.90,-\n"
#define NOTES "shared notes\nline two\n"

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

static int reads_as(const char *path, const char *want) {
  char buf[2048];
  size_t n = 0;
  ssize_t r;
  int fd = open(path, O_RDONLY);
  if (fd < 0)
    return 0;
  while (n < sizeof(buf) - 1 && (r = read(fd, buf + n, sizeof(buf) - 1 - n)) > 0)
    n += (size_t)r;
  buf[n] = '\0';
  close(fd);
  if (strcmp(buf, want) != 0)
    printf("%s reads as:\n%s", path, buf);
  return strcmp(buf, want) == 0;
}

/* Whether open(path, flags) fails with EACCES. */
static int refused(const char *path, int flags) {
  int fd;
  errno = 0;
  fd = open(path, flags);
  if (fd >= 0)
    close(fd);
  return fd == -1 && errno == EACCES;
}

int main(void) {
  CHECK("card numbers and tokens masked, debug lines gone", reads_as("/uvg_payments.log", PAYMENTS));
  CHECK("invoice columns hidden", reads_as("/uvg_invoices.csv", INVOICES));

  /* A view that rewrites lines cannot be written back, so it is read-only. */
  CHECK("write-only open refused", refused("/uvg_payments.log", O_WRONLY));
  CHECK("read-write open refused", refused("/uvg_payments.log", O_RDWR));
  CHECK("append refused", refused("/uvg_payments.log", O_WRONLY | O_APPEND));
  CHECK("truncating open refused", refused("/uvg_payments.log", O_RDONLY | O_TRUNC));
  errno = 0;
  CHECK("truncate refused", truncate("/uvg_payments.log", 0) == -1 && errno == EACCES);
  errno = 0;
  CHECK("unlink refused", unlink("/uvg_payments.log") == -1 && errno == EACCES);
  CHECK("log is still whole", reads_as("/uvg_payments.log", PAYMENTS));

  CHECK("deny", refused("/uvg_secret", O_RDONLY));
  CHECK("a user no block names is denied", refused("/uvg_audit.log", O_RDONLY));

  CHECK("readonly shows every line", reads_as("/uvg_notes", NOTES));
  CHECK("readonly refuses writing", refused("/uvg_notes", O_WRONLY));

  printf("%s: %d failure(s)\n", failures ? "FAILED" : "OK", failures);
  return failures ? 1 : 0;
}
