/* user-view-grate, run as alice: she sees and may rewrite only her own line of /uvg_shadow.
 *
 * The last thing this test does is leave FINAL as her line. uvg_raw_test.c then runs as root
 * and checks what the real file holds, so the two run in this order. */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define SHADOW "/uvg_shadow"
#define ORIGINAL "alice:$6$alicesalt$alicehash:19500:0:99999:7:::\n"
#define LINE1 "alice:$6$new$hash1:20000:0:99999:7:::\n"
#define LINE2 "alice:second:20000::::::\n"
#define FINAL "alice:$6$final$hash:20001:0:99999:7:::\n"

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

/* Whether reading `path` to the end gives exactly `want`. */
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
  return strcmp(buf, want) == 0;
}

/* Replace the open view with `text`. */
static int put(int fd, const char *text) {
  size_t len = strlen(text);
  return ftruncate(fd, 0) == 0 && pwrite(fd, text, len, 0) == (ssize_t)len;
}

/* Open the view, replace it with `text`, close it. Returns what close() returned. */
static int rewrite(const char *text) {
  int fd = open(SHADOW, O_WRONLY | O_TRUNC);
  if (fd < 0)
    return -2;
  if (write(fd, text, strlen(text)) != (ssize_t)strlen(text)) {
    close(fd);
    return -2;
  }
  return close(fd);
}

int main(void) {
  struct stat st;
  char buf[256];
  int fd, fd2, other, ret;

  chdir("/");
  /* Scratch files of this test go in /tmp, which a bare lindfs does not have. */
  mkdir("/tmp", 0777);

  /* ---- reading: the view is one line, however the file is reached ---- */
  CHECK("own line only", reads_as(SHADOW, ORIGINAL));
  CHECK("relative path", reads_as("uvg_shadow", ORIGINAL));
  CHECK("path with ..", reads_as("/tmp/../uvg_shadow", ORIGINAL));

  unlink("/tmp/uvg_sym");
  CHECK("make symlink", symlink(SHADOW, "/tmp/uvg_sym") == 0);
  CHECK("through a symlink", reads_as("/tmp/uvg_sym", ORIGINAL));
  CHECK("remove symlink", unlink("/tmp/uvg_sym") == 0);

  /* A hard link is the same file under another name. alice cannot remove it again (that would
   * be removing the protected file), so an earlier run may have left it. */
  ret = link(SHADOW, "/tmp/uvg_hard");
  if (ret == 0 || errno == EEXIST)
    CHECK("through a hard link", reads_as("/tmp/uvg_hard", ORIGINAL));
  else
    printf("SKIP: hard link (errno=%d)\n", errno);

  fd = openat(AT_FDCWD, SHADOW, O_RDONLY);
  CHECK("openat AT_FDCWD", fd >= 0 && read(fd, buf, sizeof(buf)) == (ssize_t)strlen(ORIGINAL));
  close(fd);
  other = open("/", O_RDONLY | O_DIRECTORY);
  fd = openat(other, "uvg_shadow", O_RDONLY);
  CHECK("openat dirfd", fd >= 0 && read(fd, buf, sizeof(buf)) == (ssize_t)strlen(ORIGINAL));
  close(other);

  /* The descriptor is an ordinary file holding the view: size, offsets and mmap agree. */
  CHECK("fstat size", fstat(fd, &st) == 0 && st.st_size == (off_t)strlen(ORIGINAL));
  CHECK("lseek end", lseek(fd, 0, SEEK_END) == (off_t)strlen(ORIGINAL));
  CHECK("pread", pread(fd, buf, 5, 6) == 5 && memcmp(buf, "$6$al", 5) == 0);
  {
    void *map = mmap(NULL, strlen(ORIGINAL), PROT_READ, MAP_PRIVATE, fd, 0);
    CHECK("mmap", map != MAP_FAILED && memcmp(map, ORIGINAL, strlen(ORIGINAL)) == 0);
    if (map != MAP_FAILED)
      munmap(map, strlen(ORIGINAL));
  }
  CHECK("read-only view rejects write", write(fd, "x", 1) == -1);
  close(fd);

  /* ---- writing her own line ---- */
  CHECK("rewrite own line", rewrite(LINE1) == 0);
  CHECK("rewrite is visible", reads_as(SHADOW, LINE1));

  /* ---- writing anything else is refused, and reported by close or fsync ---- */
  errno = 0;
  CHECK("line for root refused at close", rewrite("root::0:0:::::\n") == -1 && errno == EPERM);
  errno = 0;
  CHECK("extra line for bob refused",
        rewrite("alice:x:1::::::\nbob:stolen:1::::::\n") == -1 && errno == EPERM);
  CHECK("refused edits changed nothing", reads_as(SHADOW, LINE1));

  fd = open(SHADOW, O_WRONLY | O_TRUNC);
  CHECK("open for fsync test", fd >= 0);
  write(fd, "bob:stolen:1::::::\n", 19);
  errno = 0;
  CHECK("fsync reports a refused edit", fsync(fd) == -1 && errno == EPERM);
  CHECK("fix the edit", put(fd, LINE1));
  CHECK("fsync applies a good edit", fsync(fd) == 0);
  CHECK("close after fsync", close(fd) == 0);
  CHECK("still her line", reads_as(SHADOW, LINE1));

  /* ---- a second line of her own, then back to one ---- */
  fd = open(SHADOW, O_WRONLY | O_APPEND);
  CHECK("append own line", fd >= 0 && write(fd, LINE2, strlen(LINE2)) == (ssize_t)strlen(LINE2));
  CHECK("close append", close(fd) == 0);
  CHECK("two lines", reads_as(SHADOW, LINE1 LINE2));
  CHECK("back to one line", rewrite(LINE1) == 0 && reads_as(SHADOW, LINE1));

  /* ---- the file itself cannot be cut, removed, moved or replaced ---- */
  errno = 0;
  CHECK("truncate refused", truncate(SHADOW, 0) == -1 && errno == EACCES);
  errno = 0;
  CHECK("unlink refused", unlink(SHADOW) == -1 && errno == EACCES);
  errno = 0;
  CHECK("rename away refused", rename(SHADOW, "/tmp/uvg_moved") == -1 && errno == EACCES);
  other = open("/tmp/uvg_other", O_CREAT | O_WRONLY | O_TRUNC, 0644);
  write(other, "root::0:0:::::\n", 15);
  close(other);
  errno = 0;
  CHECK("rename over refused", rename("/tmp/uvg_other", SHADOW) == -1 && errno == EACCES);
  unlink("/tmp/uvg_other");
  errno = 0;
  CHECK("O_EXCL sees the file", open(SHADOW, O_CREAT | O_EXCL | O_WRONLY, 0600) == -1 && errno == EEXIST);
  errno = 0;
  CHECK("O_DIRECTORY refused", open(SHADOW, O_RDONLY | O_DIRECTORY) == -1 && errno == ENOTDIR);
  CHECK("still intact", reads_as(SHADOW, LINE1));

  /* ---- descriptors that multiply: the edit lands when the last one goes ---- */
  fd = open(SHADOW, O_RDWR);
  fd2 = dup(fd);
  CHECK("dup", fd >= 0 && fd2 >= 0);
  CHECK("close original", close(fd) == 0);
  CHECK("write through the dup", put(fd2, "alice:via-dup:1::::::\n"));
  CHECK("close dup", close(fd2) == 0);
  CHECK("dup edit applied", reads_as(SHADOW, "alice:via-dup:1::::::\n"));

  {
    int go[2];
    char byte = 'g';
    pid_t pid;
    int status = -1;

    CHECK("pipe", pipe(go) == 0);
    fd = open(SHADOW, O_RDWR);
    pid = fork();
    if (pid == 0) {
      /* Write only after the parent has closed its copy, and leave without closing. */
      close(go[1]);
      if (read(go[0], &byte, 1) != 1)
        _exit(2);
      _exit(put(fd, "alice:via-child:1::::::\n") ? 0 : 3);
    }
    CHECK("fork", pid > 0);
    close(go[0]);
    CHECK("parent closes first", close(fd) == 0);
    write(go[1], &byte, 1);
    close(go[1]);
    CHECK("child exited cleanly", waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK("child's edit applied at its exit", reads_as(SHADOW, "alice:via-child:1::::::\n"));
  }

  fd = open(SHADOW, O_RDWR);
  other = open("/tmp/uvg_plain", O_CREAT | O_RDWR | O_TRUNC, 0644);
  CHECK("open for dup2 test", fd >= 0 && other >= 0);
  CHECK("write before dup2", put(fd, "alice:via-dup2:1::::::\n"));
  CHECK("dup2 over the view", dup2(other, fd) == fd);
  CHECK("dup2 applied the edit", reads_as(SHADOW, "alice:via-dup2:1::::::\n"));
  close(fd);
  close(other);

  /* ---- other files are untouched, O_TRUNC included ---- */
  fd = open("/tmp/uvg_plain", O_WRONLY | O_TRUNC);
  CHECK("plain file write", fd >= 0 && write(fd, "long content\n", 13) == 13 && close(fd) == 0);
  fd = open("/tmp/uvg_plain", O_WRONLY | O_TRUNC);
  CHECK("plain file truncating open", fd >= 0 && write(fd, "s\n", 2) == 2 && close(fd) == 0);
  CHECK("plain file content", reads_as("/tmp/uvg_plain", "s\n"));
  CHECK("plain file unlink", unlink("/tmp/uvg_plain") == 0);
  fd = open("/tmp/uvg_new", O_CREAT | O_EXCL | O_WRONLY, 0644);
  CHECK("plain O_EXCL create", fd >= 0);
  close(fd);
  errno = 0;
  CHECK("plain O_EXCL again", open("/tmp/uvg_new", O_CREAT | O_EXCL | O_WRONLY, 0644) == -1 && errno == EEXIST);
  unlink("/tmp/uvg_new");

  /* ---- what uvg_raw_test.c expects to find ---- */
  CHECK("final line", rewrite(FINAL) == 0 && reads_as(SHADOW, FINAL));

  printf("%s: %d failure(s)\n", failures ? "FAILED" : "OK", failures);
  return failures ? 1 : 0;
}
