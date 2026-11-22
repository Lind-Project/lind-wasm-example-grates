/* api-key-grate with a key that comes from the environment.
 *
 * The grate is started with DEMO_API_KEY set to the real key (`lind-wasm --env`). This program,
 * started by the grate, must find the placeholder under that name, and the key must still reach
 * the API. The servers are in akg_common.h.
 */
#include "akg_common.h"

int main(void) {
  char req[512], echoed[512];
  pid_t api, other;
  int fd, len;

  holder = getenv("DEMO_API_KEY");
  klen = strlen(KEY);
  CHECK("the variable is set", holder != NULL);
  if (holder == NULL)
    return 1;
  CHECK("it is not the key the grate was given", strcmp(holder, KEY) != 0);
  CHECK("it has the key's length and start", strlen(holder) == klen && strncmp(holder, KEY, 4) == 0);

  api = start_server(API_PORT);
  other = start_server(OTHER_PORT);
  CHECK("servers started", api > 0 && other > 0);
  if (api <= 0 || other <= 0)
    return 1;

  len = snprintf(req, sizeof(req), "CHECK Authorization: Bearer %s\n\n", holder);
  snprintf(echoed, sizeof(echoed), "you sent %s and again %s\n", holder, holder);

  fd = dial(API_PORT);
  CHECK("the API got the key", write(fd, req, len) == len && replied(fd, "KEY"));
  close(fd);

  fd = dial(OTHER_PORT);
  CHECK("another host got only the placeholder", write(fd, req, len) == len && replied(fd, "PLACEHOLDER"));
  close(fd);

  fd = dial(API_PORT);
  write(fd, "ECHO\n\n", 6);
  slurp(fd);
  CHECK("the key does not come back", strcmp(reply, echoed) == 0);
  close(fd);

  return finish(api, other);
}
