/* Shared by the api-key-grate tests: the made-up key, and two servers that run as child
 * processes of the test.
 *
 * The "API" listens on 127.0.0.1:18080, which test/akg_test.conf allows the key to go to.
 * Another host listens on 18081, which it does not. The servers know the real key because it
 * is spelled out here (it has to be the same as test/akg_demo.key). The client side of a test
 * is given only what the grate gives it.
 *
 * A request ends with an empty line and gets one reply, after which the server closes.
 *   CHECK ...   reply says what the request held: KEY, PLACEHOLDER, BOTH or NONE
 *   ECHO        reply holds the key, twice
 *   SPLIT       reply holds the key, sent in two parts a moment apart
 *   DRAIN       no reply: the server reads until the client closes
 *   QUIT        the server exits
 */
#ifndef AKG_COMMON_H
#define AKG_COMMON_H

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#define KEY "sk-demo-7Qp2Xv9Lm4Zr8Tn6Wb3Hc5Jd1Kf0Gs"
#define KEY_FILE "/akg_demo.key"
#define SCRATCH "/akg_scratch"
#define API_PORT 18080
#define OTHER_PORT 18081

static int checks, failures;
static const char *holder; /* the placeholder */
static size_t klen;

#define CHECK(name, cond)                                 \
  do {                                                    \
    checks++;                                             \
    if (!(cond)) {                                        \
      failures++;                                         \
      printf("FAIL: %s (errno=%d)\n", name, errno);       \
    }                                                     \
  } while (0)

static int has(const char *buf, size_t n, const char *needle) {
  size_t m = strlen(needle);
  for (size_t i = 0; i + m <= n; i++)
    if (memcmp(buf + i, needle, m) == 0)
      return 1;
  return 0;
}

static struct sockaddr_in local(int port) {
  struct sockaddr_in a;
  memset(&a, 0, sizeof(a));
  a.sin_family = AF_INET;
  a.sin_port = htons(port);
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  return a;
}

static int listen_on(int port) {
  struct sockaddr_in a = local(port);
  int one = 1;
  int s = socket(AF_INET, SOCK_STREAM, 0);
  setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  if (bind(s, (struct sockaddr *)&a, sizeof(a)) != 0 || listen(s, 16) != 0)
    return -1;
  return s;
}

static int dial(int port) {
  struct sockaddr_in a = local(port);
  int s = socket(AF_INET, SOCK_STREAM, 0);
  if (connect(s, (struct sockaddr *)&a, sizeof(a)) != 0) {
    close(s);
    return -1;
  }
  return s;
}

/* ------------------------------------------------------------------ the servers */

static void put(int fd, const char *text) { write(fd, text, strlen(text)); }

static void serve(int listener) {
  for (;;) {
    char req[4096];
    size_t n = 0;
    ssize_t r;
    int c = accept(listener, NULL, NULL);
    if (c < 0)
      _exit(3);
    while (n < sizeof(req) - 1 && !has(req, n, "\n\n") &&
           (r = read(c, req + n, sizeof(req) - 1 - n)) > 0)
      n += (size_t)r;
    req[n] = '\0';

    if (strncmp(req, "QUIT", 4) == 0) {
      close(c);
      _exit(0);
    } else if (strncmp(req, "DRAIN", 5) == 0) {
      while (read(c, req, sizeof(req)) > 0)
        ;
    } else if (strncmp(req, "ECHO", 4) == 0) {
      put(c, "you sent " KEY " and again " KEY "\n");
    } else if (strncmp(req, "SPLIT", 5) == 0) {
      put(c, "half ");
      write(c, KEY, 20);
      usleep(100000);
      put(c, KEY + 20);
      put(c, " done\n");
    } else {
      int key = has(req, n, KEY), ph = has(req, n, holder);
      put(c, key ? (ph ? "BOTH" : "KEY") : (ph ? "PLACEHOLDER" : "NONE"));
    }
    close(c);
  }
}

static pid_t start_server(int port) {
  int listener = listen_on(port);
  pid_t pid;
  if (listener < 0)
    return -1;
  pid = fork();
  if (pid == 0)
    serve(listener);
  close(listener);
  return pid;
}

/* ------------------------------------------------------------------ the client */

static char reply[4096];

/* Everything the peer sends until it closes, read with read(). */
static size_t slurp(int fd) {
  size_t n = 0;
  ssize_t r;
  while (n < sizeof(reply) - 1 && (r = read(fd, reply + n, sizeof(reply) - 1 - n)) > 0)
    n += (size_t)r;
  reply[n] = '\0';
  return n;
}

static int replied(int fd, const char *want) {
  slurp(fd);
  if (strcmp(reply, want) != 0)
    printf("reply was: %s\n", reply);
  return strcmp(reply, want) == 0;
}

/* Stop both servers and report how the test went. Only failures were printed before this. */
static int finish(pid_t api, pid_t other) {
  int fd, status;
  fd = dial(API_PORT);
  write(fd, "QUIT\n\n", 6);
  close(fd);
  fd = dial(OTHER_PORT);
  write(fd, "QUIT\n\n", 6);
  close(fd);
  status = -1;
  CHECK("API server exited", waitpid(api, &status, 0) == api && WIFEXITED(status) && WEXITSTATUS(status) == 0);
  status = -1;
  CHECK("other server exited", waitpid(other, &status, 0) == other && WIFEXITED(status) && WEXITSTATUS(status) == 0);
  if (failures)
    printf("FAILED: %d of %d checks\n", failures, checks);
  else
    printf("OK: %d checks\n", checks);
  return failures ? 1 : 0;
}

#endif
