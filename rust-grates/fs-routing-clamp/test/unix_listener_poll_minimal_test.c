#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static int tests_run = 0;
static int tests_passed = 0;

#define SOCK_DIR "/sock"
#define POLL_PATH SOCK_DIR "/fsrouting_listener_poll_minimal.sock"
#define SELECT_PATH SOCK_DIR "/fsrouting_listener_select_minimal.sock"

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

static void set_addr(struct sockaddr_un *addr, const char *path) {
    memset(addr, 0, sizeof(*addr));
    addr->sun_family = AF_UNIX;
    strncpy(addr->sun_path, path, sizeof(addr->sun_path) - 1);
}

static int make_listener(const char *path) {
    struct sockaddr_un addr;
    int fd;

    mkdir(SOCK_DIR, 0777);
    unlink(path);

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;

    if (fcntl(fd, F_SETFD, FD_CLOEXEC) != 0)
        return -1;

    set_addr(&addr, path);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        return -1;
    if (listen(fd, 40) < 0)
        return -1;

    return fd;
}

static void client_process(const char *path) {
    struct sockaddr_un addr;
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        perror("client socket");
        _exit(10);
    }

    set_addr(&addr, path);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("client connect");
        _exit(11);
    }

    if (send(fd, "startup", 7, 0) != 7) {
        perror("client send startup");
        _exit(12);
    }

    char response[8] = {0};
    if (recv(fd, response, sizeof(response), 0) != 5 || memcmp(response, "ready", 5) != 0) {
        perror("client recv response");
        _exit(13);
    }

    close(fd);
    _exit(0);
}

static void wait_child_clean(pid_t pid) {
    int status = 0;
    CHECK("waitpid child", waitpid(pid, &status, 0) == pid);
    CHECK("client exits cleanly", WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void run_listener_poll_test(const char *path) {
    int wake_pipe[2] = {-1, -1};
    char buf[16] = {0};

    int listener = make_listener(path);
    CHECK("create unix listener outside routed prefix", listener >= 0);
    if (listener < 0)
        return;
    CHECK("create unrelated wake pipe", pipe(wake_pipe) == 0);

    pid_t pid = fork();
    CHECK("fork client", pid >= 0);
    if (pid == 0)
        client_process(path);
    if (pid < 0)
        return;

    struct pollfd pfds[2] = {
        {.fd = wake_pipe[0], .events = POLLIN, .revents = 0},
        {.fd = listener, .events = POLLIN, .revents = 0},
    };

    int poll_ret = poll(pfds, 2, 5000);
    CHECK("poll returns listener readiness", poll_ret == 1);
    CHECK("wake pipe remains not ready", pfds[0].revents == 0);
    CHECK("listener has POLLIN", (pfds[1].revents & POLLIN) != 0);

    int accepted = accept(listener, NULL, NULL);
    CHECK("accept after listener poll", accepted >= 0);
    if (accepted >= 0) {
        CHECK("read startup payload", recv(accepted, buf, sizeof(buf), 0) == 7);
        CHECK("startup payload matches", memcmp(buf, "startup", 7) == 0);
        CHECK("send ready response", send(accepted, "ready", 5, 0) == 5);
        close(accepted);
    }

    wait_child_clean(pid);

    close(wake_pipe[0]);
    close(wake_pipe[1]);
    close(listener);
    unlink(path);
}

static void run_listener_select_test(const char *path) {
    int wake_pipe[2] = {-1, -1};
    char buf[16] = {0};

    int listener = make_listener(path);
    CHECK("create unix listener outside routed prefix for select", listener >= 0);
    if (listener < 0)
        return;
    CHECK("create unrelated wake pipe for select", pipe(wake_pipe) == 0);

    pid_t pid = fork();
    CHECK("fork select client", pid >= 0);
    if (pid == 0)
        client_process(path);
    if (pid < 0)
        return;

    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(wake_pipe[0], &readfds);
    FD_SET(listener, &readfds);
    int nfds = (wake_pipe[0] > listener ? wake_pipe[0] : listener) + 1;
    struct timeval tv = {.tv_sec = 5, .tv_usec = 0};

    int select_ret = select(nfds, &readfds, NULL, NULL, &tv);
    CHECK("select returns listener readiness", select_ret == 1);
    CHECK("wake pipe remains not selected", !FD_ISSET(wake_pipe[0], &readfds));
    CHECK("listener selected for read", FD_ISSET(listener, &readfds));

    int accepted = accept(listener, NULL, NULL);
    CHECK("accept after listener select", accepted >= 0);
    if (accepted >= 0) {
        CHECK("read startup payload after select", recv(accepted, buf, sizeof(buf), 0) == 7);
        CHECK("startup payload matches after select", memcmp(buf, "startup", 7) == 0);
        CHECK("send ready response after select", send(accepted, "ready", 5, 0) == 5);
        close(accepted);
    }

    wait_child_clean(pid);

    close(wake_pipe[0]);
    close(wake_pipe[1]);
    close(listener);
    unlink(path);
}

int main(void) {
    signal(SIGALRM, timeout_handler);
    alarm(30);

    printf("=== fs-routing unix listener poll/select minimal test ===\n");

    printf("\n[test_listener_poll]\n");
    run_listener_poll_test(POLL_PATH);

    printf("\n[test_listener_select]\n");
    run_listener_select_test(SELECT_PATH);

    printf("\n=== results: %d/%d passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
