#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static int tests_run = 0;
static int tests_passed = 0;

#define SOCK_DIR "/sock"
#define LIBPQ_PATH SOCK_DIR "/fsrouting_libpq_style.sock"
#define MSG_PATH SOCK_DIR "/fsrouting_msg_io.sock"
#define FD_PATH SOCK_DIR "/fsrouting_fd_lifecycle.sock"

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

    set_addr(&addr, path);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        return -1;
    if (listen(fd, 4) < 0)
        return -1;

    return fd;
}

static int connect_blocking(const char *path) {
    struct sockaddr_un addr;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;

    set_addr(&addr, path);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        return -1;

    return fd;
}

static void wait_child_clean(pid_t pid, const char *desc) {
    int status = 0;
    CHECK("waitpid child", waitpid(pid, &status, 0) == pid);
    CHECK(desc, WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void child_libpq_style(void) {
    struct sockaddr_un addr;
    char buf[16] = {0};
    int err = -1;
    socklen_t err_len = sizeof(err);
    int sock_type = SOCK_STREAM;

#ifdef SOCK_CLOEXEC
    sock_type |= SOCK_CLOEXEC;
#endif
#ifdef SOCK_NONBLOCK
    sock_type |= SOCK_NONBLOCK;
#endif

    int fd = socket(AF_UNIX, sock_type, 0);
    if (fd < 0) {
        perror("child socket");
        _exit(10);
    }

#ifdef SOCK_CLOEXEC
    int fd_flags = fcntl(fd, F_GETFD);
    if (fd_flags < 0 || !(fd_flags & FD_CLOEXEC)) {
        fprintf(stderr, "child socket missing FD_CLOEXEC\n");
        _exit(11);
    }
#endif

    int flags = fcntl(fd, F_GETFL);
    if (flags < 0) {
        perror("child fcntl F_GETFL");
        _exit(12);
    }

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        perror("child fcntl F_SETFL O_NONBLOCK");
        _exit(13);
    }

    set_addr(&addr, LIBPQ_PATH);
    int connect_ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (connect_ret < 0 && errno != EINPROGRESS) {
        perror("child connect");
        _exit(14);
    }

    struct pollfd pfd = {.fd = fd, .events = POLLOUT | POLLERR, .revents = 0};
    if (poll(&pfd, 1, 5000) != 1) {
        perror("child poll connect");
        _exit(15);
    }
    if (!(pfd.revents & (POLLOUT | POLLERR))) {
        fprintf(stderr, "child poll unexpected revents=%d\n", pfd.revents);
        _exit(16);
    }

    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &err_len) < 0 || err != 0) {
        errno = err;
        perror("child getsockopt SO_ERROR");
        _exit(17);
    }

    socklen_t addr_len = sizeof(addr);
    if (getsockname(fd, (struct sockaddr *)&addr, &addr_len) < 0) {
        perror("child getsockname");
        _exit(18);
    }
    addr_len = sizeof(addr);
    if (getpeername(fd, (struct sockaddr *)&addr, &addr_len) < 0) {
        perror("child getpeername");
        _exit(19);
    }

    if (fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) < 0) {
        perror("child fcntl restore flags");
        _exit(20);
    }

#ifdef MSG_NOSIGNAL
    if (send(fd, "ping", 4, MSG_NOSIGNAL) != 4) {
#else
    if (send(fd, "ping", 4, 0) != 4) {
#endif
        perror("child send");
        _exit(21);
    }

    if (recv(fd, buf, sizeof(buf), 0) != 4 || memcmp(buf, "pong", 4) != 0) {
        perror("child recv");
        _exit(22);
    }

    close(fd);
    _exit(0);
}

static void test_libpq_style_socket(void) {
    struct sockaddr_un local_addr;
    struct sockaddr_un peer_addr;
    socklen_t local_len = sizeof(local_addr);
    socklen_t peer_len = sizeof(peer_addr);
    char buf[16] = {0};

    printf("\n[test_libpq_style_socket]\n");

    CHECK("mkdir /sock outside routed prefix",
          mkdir(SOCK_DIR, 0777) == 0 || errno == EEXIST);

    int server = make_listener(LIBPQ_PATH);
    CHECK("server socket/bind/listen outside routed prefix", server >= 0);
    if (server < 0)
        return;

    CHECK("server fcntl F_GETFD", fcntl(server, F_GETFD) >= 0);
    CHECK("server fcntl F_GETFL", fcntl(server, F_GETFL) >= 0);
    CHECK("getsockname listening unix socket",
          getsockname(server, (struct sockaddr *)&local_addr, &local_len) == 0);

    pid_t pid = fork();
    CHECK("fork libpq-style client", pid >= 0);
    if (pid == 0)
        child_libpq_style();
    if (pid < 0)
        return;

    int accepted = accept(server, NULL, NULL);
    CHECK("accept unix socket outside routed prefix", accepted >= 0);
    if (accepted >= 0) {
        struct pollfd pfd = {.fd = accepted, .events = POLLIN | POLLERR, .revents = 0};
        fd_set readfds;
        struct timeval tv = {.tv_sec = 5, .tv_usec = 0};
        CHECK("poll accepted socket for read", poll(&pfd, 1, 5000) == 1);
        FD_ZERO(&readfds);
        FD_SET(accepted, &readfds);
        CHECK("select accepted socket for read",
              select(accepted + 1, &readfds, NULL, NULL, &tv) == 1);
        CHECK("accepted fd fcntl F_GETFD", fcntl(accepted, F_GETFD) >= 0);
        CHECK("accepted fd fcntl F_GETFL", fcntl(accepted, F_GETFL) >= 0);
        CHECK("getpeername accepted unix socket",
              getpeername(accepted, (struct sockaddr *)&peer_addr, &peer_len) == 0);
        CHECK("parent recv client payload", recv(accepted, buf, sizeof(buf), 0) == 4);
        CHECK("client payload matches", memcmp(buf, "ping", 4) == 0);
#ifdef MSG_NOSIGNAL
        CHECK("parent send MSG_NOSIGNAL response", send(accepted, "pong", 4, MSG_NOSIGNAL) == 4);
#else
        CHECK("parent send response", send(accepted, "pong", 4, 0) == 4);
#endif
        close(accepted);
    }

    wait_child_clean(pid, "libpq-style client exits cleanly");
    close(server);
    unlink(LIBPQ_PATH);
}

static void child_msg_io(void) {
    char buf[16] = {0};
    char msg1[] = "msg";
    char msg2[16] = {0};
    struct iovec iov = {.iov_base = msg1, .iov_len = 3};
    struct msghdr msg = {0};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    int fd = connect_blocking(MSG_PATH);
    if (fd < 0) {
        perror("child msg connect");
        _exit(30);
    }

    if (sendto(fd, "to", 2, 0, NULL, 0) != 2) {
        perror("child sendto");
        _exit(31);
    }
    if (recvfrom(fd, buf, sizeof(buf), 0, NULL, NULL) != 2 || memcmp(buf, "fr", 2) != 0) {
        perror("child recvfrom");
        _exit(32);
    }
    if (sendmsg(fd, &msg, 0) != 3) {
        perror("child sendmsg");
        _exit(33);
    }

    iov.iov_base = msg2;
    iov.iov_len = sizeof(msg2);
    if (recvmsg(fd, &msg, 0) != 3 || memcmp(msg2, "ack", 3) != 0) {
        perror("child recvmsg");
        _exit(34);
    }

    close(fd);
    _exit(0);
}

static void test_message_io_variants(void) {
    char buf[16] = {0};
    char msgbuf[16] = {0};
    char ack[] = "ack";
    struct iovec iov = {.iov_base = msgbuf, .iov_len = sizeof(msgbuf)};
    struct msghdr msg = {0};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    printf("\n[test_message_io_variants]\n");

    int server = make_listener(MSG_PATH);
    CHECK("message-io listener outside routed prefix", server >= 0);
    if (server < 0)
        return;

    pid_t pid = fork();
    CHECK("fork message-io client", pid >= 0);
    if (pid == 0)
        child_msg_io();
    if (pid < 0)
        return;

    int accepted = accept(server, NULL, NULL);
    CHECK("accept message-io socket", accepted >= 0);
    if (accepted >= 0) {
        CHECK("parent recvfrom client payload",
              recvfrom(accepted, buf, sizeof(buf), 0, NULL, NULL) == 2);
        CHECK("recvfrom payload matches", memcmp(buf, "to", 2) == 0);
        CHECK("parent sendto response", sendto(accepted, "fr", 2, 0, NULL, 0) == 2);
        CHECK("parent recvmsg client payload", recvmsg(accepted, &msg, 0) == 3);
        CHECK("recvmsg payload matches", memcmp(msgbuf, "msg", 3) == 0);

        iov.iov_base = ack;
        iov.iov_len = 3;
        CHECK("parent sendmsg response", sendmsg(accepted, &msg, 0) == 3);
        close(accepted);
    }

    wait_child_clean(pid, "message-io client exits cleanly");
    close(server);
    unlink(MSG_PATH);
}

static void child_fd_lifecycle(void) {
    char buf[16] = {0};
    int fd = connect_blocking(FD_PATH);
    if (fd < 0) {
        perror("child fd connect");
        _exit(40);
    }

    if (write(fd, "dup", 3) != 3) {
        perror("child fd write");
        _exit(41);
    }
    if (read(fd, buf, sizeof(buf)) != 2 || memcmp(buf, "ok", 2) != 0) {
        perror("child fd read response");
        _exit(42);
    }
    if (read(fd, buf, sizeof(buf)) != 0) {
        perror("child fd read eof");
        _exit(43);
    }

    close(fd);
    _exit(0);
}

static void test_fd_lifecycle(void) {
    char buf[16] = {0};

    printf("\n[test_fd_lifecycle]\n");

    int server = make_listener(FD_PATH);
    CHECK("fd-lifecycle listener outside routed prefix", server >= 0);
    if (server < 0)
        return;

    pid_t pid = fork();
    CHECK("fork fd-lifecycle client", pid >= 0);
    if (pid == 0)
        child_fd_lifecycle();
    if (pid < 0)
        return;

    int accepted = accept(server, NULL, NULL);
    CHECK("accept fd-lifecycle socket", accepted >= 0);
    if (accepted >= 0) {
        int dup_fd = dup(accepted);
        CHECK("dup accepted socket", dup_fd >= 0);
        int fdup_fd = fcntl(accepted, F_DUPFD, 40);
        CHECK("fcntl F_DUPFD accepted socket", fdup_fd >= 40);
        int dup2_fd = 60;
        CHECK("dup2 accepted socket", dup2(accepted, dup2_fd) == dup2_fd);
        CHECK("F_SETFD FD_CLOEXEC on socket dup", fcntl(dup_fd, F_SETFD, FD_CLOEXEC) == 0);
        CHECK("F_GETFD sees FD_CLOEXEC", (fcntl(dup_fd, F_GETFD) & FD_CLOEXEC) != 0);
        CHECK("read through dup fd", read(dup_fd, buf, sizeof(buf)) == 3);
        CHECK("dup fd payload matches", memcmp(buf, "dup", 3) == 0);
        CHECK("write through F_DUPFD fd", write(fdup_fd, "ok", 2) == 2);
        CHECK("shutdown write side through dup2 fd", shutdown(dup2_fd, SHUT_WR) == 0);

        close(dup2_fd);
        close(fdup_fd);
        close(dup_fd);
        close(accepted);
    }

    wait_child_clean(pid, "fd-lifecycle client exits cleanly");
    close(server);
    unlink(FD_PATH);
}

int main(void) {
    signal(SIGALRM, timeout_handler);
    alarm(30);

    printf("=== fs-routing AF_UNIX outside-prefix test ===\n");
    test_libpq_style_socket();
    test_message_io_variants();
    test_fd_lifecycle();

    printf("\n=== results: %d/%d passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
