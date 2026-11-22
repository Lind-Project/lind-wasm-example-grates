/* api-key-grate: a program that uses an API key it can never read.
 *
 * The servers it talks to, and the key they know, are in akg_common.h. This side is given only
 * what the grate gives it: the environment variable and the key file.
 */
#include "akg_common.h"

int main(void) {
  char req[512], echoed[512], buf[512];
  struct iovec iov[2];
  struct msghdr msg;
  struct stat st;
  pid_t api, other, pid;
  int fd, fd2, file, status, len, n;
  size_t got;
  ssize_t r;

  /* ---- what the program is given in place of the key ---- */
  holder = getenv("DEMO_API_KEY");
  klen = strlen(KEY);
  CHECK("the variable is set", holder != NULL);
  if (holder == NULL)
    return 1;
  CHECK("placeholder has the key's length", strlen(holder) == klen);
  CHECK("placeholder is not the key", strcmp(holder, KEY) != 0);
  CHECK("placeholder starts like the key", strncmp(holder, KEY, 4) == 0);
  CHECK("placeholder keeps the key's punctuation", holder[2] == '-' && holder[7] == '-');

  fd = open(KEY_FILE, O_RDONLY);
  r = read(fd, buf, sizeof(buf));
  CHECK("key file reads as the placeholder",
        r == (ssize_t)klen + 1 && memcmp(buf, holder, klen) == 0 && buf[klen] == '\n');
  CHECK("key file at an offset", pread(fd, buf, 10, 8) == 10 && memcmp(buf, holder + 8, 10) == 0);
  lseek(fd, 0, SEEK_SET);
  for (got = 0; got < klen && read(fd, buf + got, 1) == 1; got++)
    ;
  CHECK("key file a byte at a time", got == klen && memcmp(buf, holder, klen) == 0);
  lseek(fd, 3, SEEK_SET);
  iov[0].iov_base = buf;
  iov[0].iov_len = 5;
  iov[1].iov_base = buf + 100;
  iov[1].iov_len = 100;
  r = readv(fd, iov, 2);
  CHECK("key file into two buffers",
        r == (ssize_t)klen - 2 && memcmp(buf, holder + 3, 5) == 0 &&
            memcmp(buf + 100, holder + 8, klen - 8) == 0);
  CHECK("key file has the size it has on disk", fstat(fd, &st) == 0 && st.st_size == (off_t)klen + 1);
  errno = 0;
  CHECK("key file cannot be mapped",
        mmap(NULL, klen, PROT_READ, MAP_PRIVATE, fd, 0) == MAP_FAILED && errno == EACCES);
  close(fd);
  if (link(KEY_FILE, "/akg_link") == 0) {
    fd = open("/akg_link", O_RDONLY);
    r = read(fd, buf, sizeof(buf));
    CHECK("key file by another name", r == (ssize_t)klen + 1 && memcmp(buf, holder, klen) == 0);
    close(fd);
    unlink("/akg_link");
  }

  /* An ordinary file is read and mapped as ever. */
  file = open(SCRATCH, O_CREAT | O_RDWR | O_TRUNC, 0600);
  CHECK("ordinary file", file >= 0 && write(file, "plain text\n", 11) == 11);
  CHECK("ordinary file read", pread(file, buf, 11, 0) == 11 && memcmp(buf, "plain text\n", 11) == 0);
  {
    void *map = mmap(NULL, 11, PROT_READ, MAP_PRIVATE, file, 0);
    CHECK("ordinary file mapped", map != MAP_FAILED && memcmp(map, "plain text\n", 11) == 0);
    if (map != MAP_FAILED)
      munmap(map, 11);
  }
  close(file);

  api = start_server(API_PORT);
  other = start_server(OTHER_PORT);
  CHECK("servers started", api > 0 && other > 0);
  if (api <= 0 || other <= 0)
    return 1;

  len = snprintf(req, sizeof(req), "CHECK Authorization: Bearer %s\n\n", holder);
  snprintf(echoed, sizeof(echoed), "you sent %s and again %s\n", holder, holder);

  /* ---- going out: the placeholder becomes the key on the way to the API, and only there ---- */
  fd = dial(API_PORT);
  CHECK("connect to the API", fd >= 0);
  CHECK("write reports what the program wrote", write(fd, req, len) == len);
  CHECK("write: the API got the key", replied(fd, "KEY"));
  close(fd);

  fd = dial(OTHER_PORT);
  CHECK("write elsewhere", write(fd, req, len) == len);
  CHECK("another host got only the placeholder", replied(fd, "PLACEHOLDER"));
  close(fd);

  fd = dial(API_PORT);
  CHECK("send", send(fd, req, len, 0) == len);
  CHECK("send: the API got the key", replied(fd, "KEY"));
  close(fd);

  /* In two buffers of one call the placeholder is still one placeholder. */
  n = snprintf(buf, sizeof(buf), "CHECK x-api-key: %.10s", holder);
  iov[0].iov_base = buf;
  iov[0].iov_len = n;
  snprintf(buf + 200, sizeof(buf) - 200, "%s\n\n", holder + 10);
  iov[1].iov_base = buf + 200;
  iov[1].iov_len = strlen(buf + 200);
  fd = dial(API_PORT);
  CHECK("writev", writev(fd, iov, 2) == (ssize_t)(iov[0].iov_len + iov[1].iov_len));
  CHECK("writev: the API got the key", replied(fd, "KEY"));
  close(fd);

  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = iov;
  msg.msg_iovlen = 2;
  fd = dial(API_PORT);
  CHECK("sendmsg", sendmsg(fd, &msg, 0) == (ssize_t)(iov[0].iov_len + iov[1].iov_len));
  CHECK("sendmsg: the API got the key", replied(fd, "KEY"));
  close(fd);

  /* Split over two calls it is not recognized, and goes out as it is. */
  fd = dial(API_PORT);
  write(fd, iov[0].iov_base, iov[0].iov_len);
  write(fd, iov[1].iov_base, iov[1].iov_len);
  CHECK("a placeholder split over two writes stays a placeholder", replied(fd, "PLACEHOLDER"));
  close(fd);

  fd = dial(API_PORT);
  write(fd, "CHECK no key in this one\n\n", 26);
  CHECK("a request without the placeholder is untouched", replied(fd, "NONE"));
  close(fd);

  /* ---- coming in: a key the API sends back arrives as the placeholder ---- */
  fd = dial(API_PORT);
  write(fd, "ECHO\n\n", 6);
  got = slurp(fd);
  CHECK("read: the key does not come back", !has(reply, got, KEY));
  CHECK("read: the placeholder comes back in its place", strcmp(reply, echoed) == 0);
  close(fd);

  fd = dial(API_PORT);
  write(fd, "ECHO\n\n", 6);
  for (got = 0; got < sizeof(reply) - 1 && read(fd, reply + got, 1) == 1; got++)
    ;
  reply[got] = '\0';
  CHECK("read a byte at a time", strcmp(reply, echoed) == 0);
  close(fd);

  fd = dial(API_PORT);
  write(fd, "ECHO\n\n", 6);
  for (got = 0; (r = recv(fd, reply + got, 7, 0)) > 0; got += (size_t)r)
    ;
  reply[got] = '\0';
  CHECK("recv", strcmp(reply, echoed) == 0);
  close(fd);

  fd = dial(API_PORT);
  write(fd, "ECHO\n\n", 6);
  got = 0;
  do {
    iov[0].iov_base = reply + got;
    iov[0].iov_len = 11;
    iov[1].iov_base = reply + got + 11;
    iov[1].iov_len = 13;
    r = readv(fd, iov, 2);
    if (r > 0)
      got += (size_t)r;
  } while (r > 0);
  reply[got] = '\0';
  CHECK("readv", strcmp(reply, echoed) == 0);
  close(fd);

  fd = dial(API_PORT);
  write(fd, "ECHO\n\n", 6);
  got = 0;
  do {
    iov[0].iov_base = reply + got;
    iov[0].iov_len = 9;
    iov[1].iov_base = reply + got + 9;
    iov[1].iov_len = 30;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = iov;
    msg.msg_iovlen = 2;
    r = recvmsg(fd, &msg, 0);
    if (r > 0)
      got += (size_t)r;
  } while (r > 0);
  reply[got] = '\0';
  CHECK("recvmsg", strcmp(reply, echoed) == 0);
  close(fd);

  /* A look ahead shows the placeholder too, and the read after it is not thrown off. */
  fd = dial(API_PORT);
  write(fd, "ECHO\n\n", 6);
  r = recv(fd, buf, 30, MSG_PEEK);
  CHECK("peek", r > 0 && memcmp(buf, echoed, (size_t)r) == 0);
  slurp(fd);
  CHECK("read after a peek", strcmp(reply, echoed) == 0);
  close(fd);

  /* The key in two parts with a pause between: neither read hands over its part. */
  fd = dial(API_PORT);
  write(fd, "SPLIT\n\n", 7);
  got = 0;
  n = 0;
  while ((r = read(fd, reply + got, sizeof(reply) - 1 - got)) > 0) {
    /* The eight characters after the four a placeholder keeps. */
    n += has(reply + got, (size_t)r, "emo-7Qp2");
    got += (size_t)r;
  }
  reply[got] = '\0';
  snprintf(buf, sizeof(buf), "half %s done\n", holder);
  CHECK("a key that arrives in two parts", n == 0 && strcmp(reply, buf) == 0);
  close(fd);

  /* ---- the connection stays what it is, whatever descriptor it is used through ---- */
  fd = dial(API_PORT);
  fd2 = dup(fd);
  close(fd);
  CHECK("dup", fd2 >= 0 && write(fd2, req, len) == len && replied(fd2, "KEY"));
  close(fd2);

  fd = dial(API_PORT);
  fd2 = fcntl(fd, F_DUPFD, 100);
  close(fd);
  write(fd2, "ECHO\n\n", 6);
  slurp(fd2);
  CHECK("fcntl dup: reads are redacted through it", fd2 >= 100 && strcmp(reply, echoed) == 0);
  close(fd2);

  fd = dial(API_PORT);
  file = open(SCRATCH, O_RDWR);
  CHECK("dup2 the connection over a file", dup2(fd, file) == file);
  close(fd);
  CHECK("dup2: the API got the key", write(file, req, len) == len && replied(file, "KEY"));
  close(file);

  fd = dial(API_PORT);
  pid = fork();
  if (pid == 0) {
    int ok = write(fd, req, len) == len && replied(fd, "KEY");
    _exit(ok ? 0 : 1);
  }
  close(fd);
  status = -1;
  CHECK("fork: the child used the key", waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);

  fd = dial(API_PORT);
  pid = fork();
  if (pid == 0) {
    write(fd, "ECHO\n\n", 6);
    slurp(fd);
    _exit(strcmp(reply, echoed) == 0 ? 0 : 1);
  }
  close(fd);
  status = -1;
  CHECK("fork: the child's reads are redacted", waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);

  /* ---- a descriptor number that no longer is the connection gets no key ---- */
  fd = dial(API_PORT);
  close(fd);
  file = open(SCRATCH, O_RDWR | O_TRUNC); /* takes the number the connection had */
  CHECK("write the placeholder to a file", write(file, req, len) == len);
  CHECK("the file holds the placeholder",
        pread(file, buf, sizeof(buf), 0) == len && memcmp(buf, req, len) == 0);

  fd = dial(API_PORT);
  CHECK("dup2 a file over the connection", dup2(file, fd) == fd);
  CHECK("write through the replaced number", write(fd, req, len) == len);
  r = pread(file, buf, sizeof(buf), 0);
  CHECK("still only the placeholder in the file", r >= len && !has(buf, (size_t)r, KEY));
  close(fd);
  close(file);
  unlink(SCRATCH);

  return finish(api, other);
}
