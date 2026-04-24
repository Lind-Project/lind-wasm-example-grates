#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>


static int failures = 0;
static int total = 0;

#define PASS(x) \
    do { \
        printf("PASS: %s\n", x); \
    } while (0)

#define FAIL(x) \
    do { \
        printf("FAIL: %s (%s)\n", x, strerror(errno)); \
        failures++; \
    } while (0)

#define CHECK(x, expr) \
    do { \
        total++; \
        if (expr) PASS(x); else FAIL(x); \
    } while (0)

static void mkaddr(struct sockaddr_un *un, const char *p) {
    memset(un, 0, sizeof(*un));
    un->sun_family = AF_UNIX;
    snprintf(un->sun_path, sizeof(un->sun_path), "%s", p);
}

int main(int argc, char *argv[]) {
    char cwd[PATH_MAX];

    char *seed = "CHROOT_TEST";
    if (argc > 1) {
        strcpy(seed, argv[1]);
    }

    // ---- basic paths ----
    char dir[64];
    char a[64];
    char b[64];
    char c[64];
    char sym[64];

    snprintf(dir, sizeof(dir), "sub-%s", seed);
    snprintf(a, sizeof(a), "a.txt-%s", seed);
    snprintf(b, sizeof(b), "b.txt-%s", seed);
    snprintf(c, sizeof(c), "c.txt-%s", seed);
    snprintf(sym, sizeof(sym), "sym-%s", seed);

    // ---- mkdir ----
    CHECK("mkdir: create subdirectory", mkdir(dir, 0755) == 0 || errno == EEXIST);

    // ---- open ----
    int fd = open(a, O_CREAT | O_RDWR, 0644);
    CHECK("open: create and open file for read/write", fd >= 0);
    if (fd >= 0) {
        write(fd, "hello", 5);
        close(fd);
    }

    // ---- access ----
    CHECK("access: check file existence", access(a, F_OK) == 0);

    // ---- stat ----
    struct stat st;
    CHECK("stat: retrieve file metadata", stat(a, &st) == 0);

    // ---- chmod ----
    CHECK("chmod: change file permissions", chmod(a, 0600) == 0);

    // ---- truncate ----
    CHECK("truncate: shrink file to 1 byte", truncate(a, 1) == 0);

    // ---- link ----
    CHECK("link: create hard link", link(a, b) == 0);

    // ---- rename ----
    CHECK("rename: rename hard link", rename(b, c) == 0);

    // ---- unlink ----
    CHECK("unlink: remove original file", unlink(a) == 0);

    // ---- unlinkat ----
    int dfd = open(".", O_DIRECTORY);
    CHECK("open: open current directory as fd", dfd >= 0);
    if (dfd >= 0) {
        CHECK("unlinkat: remove renamed file via dirfd", unlinkat(dfd, c, 0) == 0);
        close(dfd);
    }

    // ---- statfs ----
    struct statfs sfs;
    CHECK("statfs: retrieve filesystem stats for cwd", statfs(".", &sfs) == 0);

    // ---- getcwd ----
    CHECK("getcwd: retrieve current working directory path", getcwd(cwd, sizeof(cwd)) != NULL);

    // ---- chroot (should fail) ----
    errno = 0;
    int cr = chroot(".");
    CHECK("chroot: must be rejected inside cage", cr == -1);

    // ---- exec outside chroot (should fail) ----
    {
        pid_t pid = fork();
        if (pid == 0) {
            // Child: try to exec a path that doesn't exist inside the chroot.
            // The grate rewrites this to <chroot>/outside_chroot_bin, which
            // shouldn't exist, so execv must fail.
            char *args[] = {"/outside_chroot_bin", NULL};
            execv("/outside_chroot_bin", args);
            // execv failed as expected — exit 0 to signal success to parent
            _exit(0);
        } else if (pid > 0) {
            int wstatus;
            waitpid(pid, &wstatus, 0);
            CHECK("exec: path outside chroot is unreachable",
                  WIFEXITED(wstatus) && WEXITSTATUS(wstatus) == 0);
        } else {
            FAIL("exec: fork failed");
        }
    }

    // ---- AF_UNIX stream ----
    const char *srvp = "sock_s";
    const char *clip = "sock_c";

    unlink(srvp);
    unlink(clip);

    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    int cfd = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK("socket: create AF_UNIX stream server and client fds", s >= 0 && cfd >= 0);

    if (s >= 0 && cfd >= 0) {
        struct sockaddr_un sa, ca;
        mkaddr(&sa, srvp);
        mkaddr(&ca, clip);

        CHECK("bind: bind server to stream socket path", bind(s, (void*)&sa, sizeof(sa)) == 0);
        CHECK("listen: mark server socket as passive", listen(s, 1) == 0);
        CHECK("bind: bind client to stream socket path", bind(cfd, (void*)&ca, sizeof(ca)) == 0);
        CHECK("connect: client connects to server stream socket", connect(cfd, (void*)&sa, sizeof(sa)) == 0);

        int acc = accept(s, NULL, NULL);
        CHECK("accept: server accepts incoming stream connection", acc >= 0);

        if (acc >= 0) {
            struct sockaddr_un tmp;
            socklen_t len = sizeof(tmp);
            CHECK("getsockname: retrieve local address of accepted socket", getsockname(acc, (void*)&tmp, &len) == 0);
            CHECK("getpeername: retrieve peer address of accepted socket", getpeername(acc, (void*)&tmp, &len) == 0);
            close(acc);
        }

        close(s);
        close(cfd);
    }

    unlink(srvp);
    unlink(clip);

    // ---- AF_UNIX datagram ----
    const char *ds = "ds";
    const char *dc = "dc";

    unlink(ds);
    unlink(dc);

    int s1 = socket(AF_UNIX, SOCK_DGRAM, 0);
    int s2 = socket(AF_UNIX, SOCK_DGRAM, 0);
    CHECK("socket: create AF_UNIX datagram server and client fds", s1 >= 0 && s2 >= 0);

    if (s1 >= 0 && s2 >= 0) {
        struct sockaddr_un a1, a2;
        mkaddr(&a1, ds);
        mkaddr(&a2, dc);

        CHECK("bind: bind server to datagram socket path", bind(s1, (void*)&a1, sizeof(a1)) == 0);
        CHECK("bind: bind client to datagram socket path", bind(s2, (void*)&a2, sizeof(a2)) == 0);

        CHECK("sendto: client sends datagram to server", sendto(s2, "x", 1, 0, (void*)&a1, sizeof(a1)) == 1);

        char rbuf[8];
        struct sockaddr_un from;
        socklen_t fl = sizeof(from);
        CHECK("recvfrom: server receives datagram with sender address", recvfrom(s1, rbuf, sizeof(rbuf), 0, (void*)&from, &fl) >= 0);

        close(s1);
        close(s2);
    }

    unlink(ds);
    unlink(dc);
    rmdir(dir);

    printf("Result (%d/%d passed).\n", (total - failures), total);

    return failures ? 1 : 0;
}
