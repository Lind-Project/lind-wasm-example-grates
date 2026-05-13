#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static int tests_run = 0;
static int tests_passed = 0;

#define SOCK_DIR "/sock"
#define SOCK_PATH SOCK_DIR "/fsrouting_outside_prefix.sock"

#define CHECK(desc, cond)                                                      \
    do {                                                                       \
        tests_run++;                                                           \
        if (cond) {                                                            \
            printf("  PASS: %s\n", desc);                                      \
            tests_passed++;                                                    \
        } else {                                                               \
            printf("  FAIL: %s (errno=%d: %s)\n", desc, errno, strerror(errno)); \
        }                                                                      \
    } while (0)

static void timeout_handler(int sig) {
    (void)sig;
    write(STDERR_FILENO, "FAIL: timed out\n", 16);
    _exit(2);
}

static void set_addr(struct sockaddr_un *addr) {
    memset(addr, 0, sizeof(*addr));
    addr->sun_family = AF_UNIX;
    strncpy(addr->sun_path, SOCK_PATH, sizeof(addr->sun_path) - 1);
}

static void child_client(void) {
    struct sockaddr_un addr;
    char buf[16] = {0};

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("child socket");
        _exit(10);
    }

    set_addr(&addr);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("child connect");
        _exit(11);
    }

    if (write(fd, "ping", 4) != 4) {
        perror("child write");
        _exit(12);
    }

    if (read(fd, buf, sizeof(buf)) != 4 || memcmp(buf, "pong", 4) != 0) {
        perror("child read");
        _exit(13);
    }

    close(fd);
    _exit(0);
}

static void test_unix_socket_outside_prefix(void) {
    struct sockaddr_un addr;
    char buf[16] = {0};

    printf("\n[test_unix_socket_outside_prefix]\n");

    CHECK("mkdir /sock outside routed prefix",
          mkdir(SOCK_DIR, 0777) == 0 || errno == EEXIST);
    unlink(SOCK_PATH);

    int server = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK("server socket outside routed prefix", server >= 0);
    if (server < 0)
        return;

    set_addr(&addr);
    CHECK("bind unix socket outside routed prefix",
          bind(server, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    CHECK("listen unix socket outside routed prefix", listen(server, 1) == 0);

    pid_t pid = fork();
    CHECK("fork client process", pid >= 0);
    if (pid == 0)
        child_client();
    if (pid < 0)
        return;

    int accepted = accept(server, NULL, NULL);
    CHECK("accept unix socket outside routed prefix", accepted >= 0);
    if (accepted >= 0) {
        CHECK("parent reads client payload", read(accepted, buf, sizeof(buf)) == 4);
        CHECK("client payload matches", memcmp(buf, "ping", 4) == 0);
        CHECK("parent writes response", write(accepted, "pong", 4) == 4);
        close(accepted);
    }

    int status = 0;
    CHECK("waitpid client", waitpid(pid, &status, 0) == pid);
    CHECK("client exits cleanly", WIFEXITED(status) && WEXITSTATUS(status) == 0);

    close(server);
    unlink(SOCK_PATH);
}

int main(void) {
    signal(SIGALRM, timeout_handler);
    alarm(20);

    printf("=== fs-routing AF_UNIX outside-prefix test ===\n");
    test_unix_socket_outside_prefix();

    printf("\n=== results: %d/%d passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
