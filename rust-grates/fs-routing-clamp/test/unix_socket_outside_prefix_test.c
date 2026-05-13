#include <errno.h>
#include <fcntl.h>
#include <poll.h>
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
    int err = -1;
    socklen_t err_len = sizeof(err);

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("child socket");
        _exit(10);
    }

    if (fcntl(fd, F_GETFD) < 0) {
        perror("child fcntl F_GETFD");
        _exit(11);
    }

    int flags = fcntl(fd, F_GETFL);
    if (flags < 0) {
        perror("child fcntl F_GETFL");
        _exit(12);
    }

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        perror("child fcntl F_SETFL O_NONBLOCK");
        _exit(13);
    }

    set_addr(&addr);
    int connect_ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (connect_ret < 0 && errno != EINPROGRESS) {
        perror("child connect");
        _exit(14);
    }

    struct pollfd pfd = {
        .fd = fd,
        .events = POLLOUT,
        .revents = 0,
    };
    if (poll(&pfd, 1, 5000) != 1) {
        perror("child poll connect");
        _exit(15);
    }
    if (!(pfd.revents & POLLOUT)) {
        fprintf(stderr, "child poll missing POLLOUT: revents=%d\n", pfd.revents);
        _exit(16);
    }

    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &err_len) < 0 || err != 0) {
        errno = err;
        perror("child getsockopt SO_ERROR");
        _exit(17);
    }

    if (fcntl(fd, F_SETFL, flags) < 0) {
        perror("child fcntl restore flags");
        _exit(18);
    }

    if (write(fd, "ping", 4) != 4) {
        perror("child write");
        _exit(19);
    }

    if (read(fd, buf, sizeof(buf)) != 4 || memcmp(buf, "pong", 4) != 0) {
        perror("child read");
        _exit(20);
    }

    close(fd);
    _exit(0);
}

static void test_unix_socket_outside_prefix(void) {
    struct sockaddr_un addr;
    struct sockaddr_un local_addr;
    struct sockaddr_un peer_addr;
    socklen_t local_len = sizeof(local_addr);
    socklen_t peer_len = sizeof(peer_addr);
    char buf[16] = {0};

    printf("\n[test_unix_socket_outside_prefix]\n");

    CHECK("mkdir /sock outside routed prefix",
          mkdir(SOCK_DIR, 0777) == 0 || errno == EEXIST);
    unlink(SOCK_PATH);

    int server = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK("server socket outside routed prefix", server >= 0);
    if (server < 0)
        return;

    CHECK("server fcntl F_GETFD", fcntl(server, F_GETFD) >= 0);
    CHECK("server fcntl F_GETFL", fcntl(server, F_GETFL) >= 0);

    set_addr(&addr);
    CHECK("bind unix socket outside routed prefix",
          bind(server, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    CHECK("listen unix socket outside routed prefix", listen(server, 1) == 0);
    CHECK("getsockname listening unix socket",
          getsockname(server, (struct sockaddr *)&local_addr, &local_len) == 0);

    pid_t pid = fork();
    CHECK("fork client process", pid >= 0);
    if (pid == 0)
        child_client();
    if (pid < 0)
        return;

    int accepted = accept(server, NULL, NULL);
    CHECK("accept unix socket outside routed prefix", accepted >= 0);
    if (accepted >= 0) {
        CHECK("accepted fd fcntl F_GETFD", fcntl(accepted, F_GETFD) >= 0);
        CHECK("accepted fd fcntl F_GETFL", fcntl(accepted, F_GETFL) >= 0);
        CHECK("getpeername accepted unix socket",
              getpeername(accepted, (struct sockaddr *)&peer_addr, &peer_len) == 0);
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
