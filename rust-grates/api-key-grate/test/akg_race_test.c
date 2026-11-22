/* api-key-grate against a program with a second thread.
 *
 * The grate decides what to do with a call by looking at what its descriptor is. A second
 * thread can make the descriptor number mean something else at that very moment. Two things it
 * could hope for, tried here many times with the timing varied:
 *
 * - A write of the placeholder to the API is under way, and the number is pointed at a file.
 *   The key must never land in the file.
 * - A thread reads an ordinary file over and over, and the number is pointed at a connection
 *   on which the API is sending the key back. The key must never be read.
 *
 * And one thing that must keep working: closing a descriptor that another thread is blocked
 * reading.
 */
#include <pthread.h>
#include <stdatomic.h>

#include "akg_common.h"

#define ROUNDS 100

static void spin(int n) {
  for (volatile int i = 0; i < n; i++)
    ;
}

/* ---- a file put where a connection is being written ---- */

struct swap {
  int from, onto, wait;
  atomic_int done;
};

static void *swapper(void *arg) {
  struct swap *s = arg;
  spin(s->wait);
  dup2(s->from, s->onto);
  atomic_store(&s->done, 1);
  return NULL;
}

/* Returns how many rounds had the file put in place partway through the writes. */
static int write_race(int *leaked) {
  static char seen[64 * 1024];
  char line[128];
  int partway = 0;
  int len = snprintf(line, sizeof(line), "token=%s\n", holder);

  for (int round = 0; round < ROUNDS; round++) {
    pthread_t thread;
    struct swap s;
    ssize_t n;
    int before = 0;
    int file = open(SCRATCH, O_CREAT | O_RDWR | O_TRUNC, 0600);
    int fd = dial(API_PORT);
    if (file < 0 || fd < 0)
      return -1;
    write(fd, "DRAIN\n\n", 7);

    s.from = file;
    s.onto = fd;
    s.wait = round * 500;
    atomic_init(&s.done, 0);
    pthread_create(&thread, NULL, swapper, &s);
    /* Write without a pause until the number has been pointed at the file, and a little more. */
    while (!atomic_load(&s.done)) {
      write(fd, line, len);
      before++;
    }
    for (int i = 0; i < 5; i++)
      write(fd, line, len);
    pthread_join(thread, NULL);

    /* Whatever was written after the swap is in the file. */
    n = pread(file, seen, sizeof(seen), 0);
    if (n > 0 && has(seen, (size_t)n, KEY))
      (*leaked)++;
    if (n > 0 && before > 1)
      partway++;
    close(fd);
    close(file);
  }
  unlink(SCRATCH);
  return partway;
}

/* ---- a connection put where a file is being read ---- */

struct reader {
  int fd;
  atomic_int stop, reads;
  int saw_key;
  size_t got;
  char data[1024];
};

static void *read_loop(void *arg) {
  struct reader *rd = arg;
  char buf[256];
  /* Until the reply, which ends with a newline, has been read. */
  while (!atomic_load(&rd->stop)) {
    ssize_t r = read(rd->fd, buf, sizeof(buf));
    atomic_fetch_add(&rd->reads, 1);
    if (r <= 0)
      continue;
    if (has(buf, (size_t)r, "emo-7Qp2"))
      rd->saw_key = 1;
    if (rd->got + (size_t)r < sizeof(rd->data)) {
      memcpy(rd->data + rd->got, buf, (size_t)r);
      rd->got += (size_t)r;
    }
    if (buf[r - 1] == '\n')
      break;
  }
  return NULL;
}

static void read_race(int *leaked, int *wrong) {
  char echoed[512];
  snprintf(echoed, sizeof(echoed), "you sent %s and again %s\n", holder, holder);

  for (int round = 0; round < ROUNDS; round++) {
    static struct reader rd;
    pthread_t thread;
    int file = open(SCRATCH, O_CREAT | O_RDWR | O_TRUNC, 0600);
    int fd = dial(API_PORT);
    if (file < 0 || fd < 0) {
      (*wrong)++;
      return;
    }
    memset(&rd, 0, sizeof(rd));
    rd.fd = file; /* empty: every read of it returns at once */
    pthread_create(&thread, NULL, read_loop, &rd);

    write(fd, "ECHO\n\n", 6);
    while (atomic_load(&rd.reads) < 3) /* the reader is at it */
      ;
    spin(round * 500);
    dup2(fd, file); /* the reader's descriptor is now the connection */
    close(fd);

    /* The reader stops by itself when it has the reply. Give it five seconds. */
    for (int i = 0; i < 5000 && rd.got < strlen(echoed); i++)
      usleep(1000);
    atomic_store(&rd.stop, 1);
    shutdown(file, SHUT_RDWR);
    pthread_join(thread, NULL);

    if (rd.saw_key || has(rd.data, rd.got, KEY))
      (*leaked)++;
    if (rd.got != strlen(echoed) || memcmp(rd.data, echoed, rd.got) != 0)
      (*wrong)++;
    close(file);
  }
  unlink(SCRATCH);
}

/* ---- closing under a blocked read ---- */

static void *block_on(void *arg) {
  char byte = 0;
  ssize_t r = read(*(int *)arg, &byte, 1);
  return (void *)(long)(r == 1 && byte == 'x');
}

int main(void) {
  pthread_t thread;
  pid_t api, other;
  void *result = NULL;
  int ends[2], leaked = 0, wrong = 0, partway;

  holder = getenv("DEMO_API_KEY");
  klen = strlen(KEY);
  CHECK("the variable is set", holder != NULL && strlen(holder) == klen);
  if (holder == NULL)
    return 1;
  api = start_server(API_PORT);
  other = start_server(OTHER_PORT);
  CHECK("servers started", api > 0 && other > 0);
  if (api <= 0 || other <= 0)
    return 1;

  partway = write_race(&leaked);
  CHECK("write race ran", partway >= 0);
  CHECK("a file put under a write never gets the key", leaked == 0);
  printf("write race: the file took over partway through in %d of %d rounds\n", partway, ROUNDS);

  leaked = 0;
  read_race(&leaked, &wrong);
  CHECK("a connection put under a read never hands over the key", leaked == 0);
  CHECK("and the reply is read whole, as the placeholder", wrong == 0);

  /* The read is waiting in the kernel on the pipe. The close goes ahead, and the read still
   * gets what is written to the pipe afterwards. */
  CHECK("pipe", pipe(ends) == 0);
  pthread_create(&thread, NULL, block_on, &ends[0]);
  usleep(50000);
  CHECK("close under a blocked read returns", close(ends[0]) == 0);
  CHECK("write to the pipe", write(ends[1], "x", 1) == 1);
  pthread_join(thread, &result);
  CHECK("the blocked read got its byte", result != NULL);
  close(ends[1]);

  return finish(api, other);
}
