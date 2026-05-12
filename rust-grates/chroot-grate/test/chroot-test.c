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
    char symhard[64];
    char symat[64];
    char missing[64];
    char absmissing[80];
    char at1[64];
    char at2[64];
    char fd_dir_name[64];
    char fd_file[64];
    char fd_dup_file[64];
    char fd_fcntl_file[64];
    char fd_child_file[64];

    snprintf(dir, sizeof(dir), "sub-%s", seed);
    snprintf(a, sizeof(a), "a.txt-%s", seed);
    snprintf(b, sizeof(b), "b.txt-%s", seed);
    snprintf(c, sizeof(c), "c.txt-%s", seed);
    snprintf(sym, sizeof(sym), "sym-%s", seed);
    snprintf(symhard, sizeof(symhard), "sym-hard-%s", seed);
    snprintf(symat, sizeof(symat), "symat-%s", seed);
    snprintf(missing, sizeof(missing), "missing-%s", seed);
    snprintf(absmissing, sizeof(absmissing), "/missing-abs-%s", seed);
    snprintf(at1, sizeof(at1), "at1.txt-%s", seed);
    snprintf(at2, sizeof(at2), "at2.txt-%s", seed);
    snprintf(fd_dir_name, sizeof(fd_dir_name), "fd-dir-%s", seed);
    snprintf(fd_file, sizeof(fd_file), "from-fchdir-%s", seed);
    snprintf(fd_dup_file, sizeof(fd_dup_file), "from-dup-fchdir-%s", seed);
    snprintf(fd_fcntl_file, sizeof(fd_fcntl_file), "from-fcntl-fchdir-%s", seed);
    snprintf(fd_child_file, sizeof(fd_child_file), "from-fork-fchdir-%s", seed);

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

    char out[64];
    char orig[72];
    snprintf(out, sizeof(out), "out.E-%s", seed);
    snprintf(orig, sizeof(orig), "%s.orig", out);
    int outfd = open(out, O_CREAT | O_RDWR, 0644);
    CHECK("open: create file for rename-open-unlink sequence", outfd >= 0);
    if (outfd >= 0) {
        CHECK("write: populate rename-open-unlink file", write(outfd, "x", 1) == 1);
        close(outfd);
        CHECK("rename: move output aside before normalization", rename(out, orig) == 0);
        int origfd = open(orig, O_RDONLY);
        CHECK("open: read renamed output file", origfd >= 0);
        CHECK("unlink: remove renamed output while open", unlink(orig) == 0);
        if (origfd >= 0) close(origfd);
    }

    // ---- symlink ----
    CHECK("symlink: create dangling relative symlink", symlink(missing, sym) == 0);
    char linkbuf[PATH_MAX];
    ssize_t linklen = readlink(sym, linkbuf, sizeof(linkbuf) - 1);
    if (linklen >= 0) {
        linkbuf[linklen] = '\0';
    }
    CHECK("readlink: relative symlink target is preserved", linklen >= 0 && strcmp(linkbuf, missing) == 0);
    CHECK("link: hardlink dangling symlink itself", link(sym, symhard) == 0);
    linklen = readlink(symhard, linkbuf, sizeof(linkbuf) - 1);
    if (linklen >= 0) {
        linkbuf[linklen] = '\0';
    }
    CHECK("readlink: hardlinked symlink target is preserved", linklen >= 0 && strcmp(linkbuf, missing) == 0);
    CHECK("unlink: remove hardlinked symlink", unlink(symhard) == 0);
    CHECK("unlink: remove relative symlink", unlink(sym) == 0);

    CHECK("symlink: create dangling absolute symlink", symlink(absmissing, sym) == 0);
    linklen = readlink(sym, linkbuf, sizeof(linkbuf) - 1);
    if (linklen >= 0) {
        linkbuf[linklen] = '\0';
    }
    CHECK("readlink: absolute symlink target succeeds", linklen >= 0);
    CHECK("unlink: remove absolute symlink", unlink(sym) == 0);

    // ---- unlink ----
    CHECK("unlink: remove original file", unlink(a) == 0);

    // ---- unlinkat ----
    int dfd = open(".", O_DIRECTORY);
    CHECK("open: open current directory as fd", dfd >= 0);
    if (dfd >= 0) {
        CHECK("unlinkat: remove renamed file via dirfd", unlinkat(dfd, c, 0) == 0);

        int atfd = openat(dfd, at1, O_CREAT | O_RDWR, 0644);
        CHECK("openat: create file relative to dirfd", atfd >= 0);
        if (atfd >= 0) {
            CHECK("write: populate openat-created file", write(atfd, "atdata", 6) == 6);
            close(atfd);
        }

        CHECK("faccessat: check dirfd-relative file", faccessat(dfd, at1, F_OK, 0) == 0);
        CHECK("fstatat: retrieve dirfd-relative metadata", fstatat(dfd, at1, &st, 0) == 0);
        CHECK("fchmodat: change dirfd-relative permissions", fchmodat(dfd, at1, 0600, 0) == 0);
        CHECK("fstatat: verify fchmodat mode", fstatat(dfd, at1, &st, 0) == 0 && (st.st_mode & 0777) == 0600);
        CHECK("utimensat: update dirfd-relative timestamps", utimensat(dfd, at1, NULL, 0) == 0);
        CHECK("unlinkat: remove fd-relative file", unlinkat(dfd, at1, 0) == 0);
        CHECK("symlinkat: create dangling symlink relative to dirfd", symlinkat(missing, dfd, symat) == 0);
        CHECK("unlinkat: remove symlinkat result", unlinkat(dfd, symat, 0) == 0);

        close(dfd);
    }

    // ---- fchdir / fd inheritance ----
    CHECK("mkdir: create fchdir target directory", mkdir(fd_dir_name, 0755) == 0 || errno == EEXIST);
    int saved_cwd = open(".", O_RDONLY);
    int dir_for_fchdir = open(fd_dir_name, O_RDONLY);
    CHECK("open: save current directory fd", saved_cwd >= 0);
    CHECK("open: open fchdir target directory", dir_for_fchdir >= 0);

    if (saved_cwd >= 0 && dir_for_fchdir >= 0) {
        char fd_file_path[128];
        char fd_dup_path[128];
        char fd_fcntl_path[128];
        char fd_child_path[128];

        snprintf(fd_file_path, sizeof(fd_file_path), "%s/%s", fd_dir_name, fd_file);
        snprintf(fd_dup_path, sizeof(fd_dup_path), "%s/%s", fd_dir_name, fd_dup_file);
        snprintf(fd_fcntl_path, sizeof(fd_fcntl_path), "%s/%s", fd_dir_name, fd_fcntl_file);
        snprintf(fd_child_path, sizeof(fd_child_path), "%s/%s", fd_dir_name, fd_child_file);

        CHECK("fchdir: move cwd using directory fd", fchdir(dir_for_fchdir) == 0);
        int ffd = open(fd_file, O_CREAT | O_RDWR, 0644);
        CHECK("open: relative create after fchdir", ffd >= 0);
        if (ffd >= 0) close(ffd);
        CHECK("fchdir: restore saved cwd", fchdir(saved_cwd) == 0);
        CHECK("access: file created under fchdir directory", access(fd_file_path, F_OK) == 0);

        int dup_dir = dup(dir_for_fchdir);
        CHECK("dup: duplicate tracked directory fd", dup_dir >= 0);
        if (dup_dir >= 0) {
            CHECK("fchdir: duplicated directory fd works", fchdir(dup_dir) == 0);
            int dfd2 = open(fd_dup_file, O_CREAT | O_RDWR, 0644);
            CHECK("open: relative create after dup fchdir", dfd2 >= 0);
            if (dfd2 >= 0) close(dfd2);
            CHECK("fchdir: restore after dup fchdir", fchdir(saved_cwd) == 0);
            CHECK("access: dup fchdir file created in directory", access(fd_dup_path, F_OK) == 0);
            close(dup_dir);
            errno = 0;
            CHECK("fchdir: closed dup fd fails", fchdir(dup_dir) == -1 && errno == EBADF);
        }

        int fcntl_dir = fcntl(dir_for_fchdir, F_DUPFD, 50);
        CHECK("fcntl: F_DUPFD duplicates tracked directory fd", fcntl_dir >= 50);
        if (fcntl_dir >= 0) {
            CHECK("fchdir: fcntl-duplicated directory fd works", fchdir(fcntl_dir) == 0);
            int ffd2 = open(fd_fcntl_file, O_CREAT | O_RDWR, 0644);
            CHECK("open: relative create after fcntl fchdir", ffd2 >= 0);
            if (ffd2 >= 0) close(ffd2);
            CHECK("fchdir: restore after fcntl fchdir", fchdir(saved_cwd) == 0);
            CHECK("access: fcntl fchdir file created in directory", access(fd_fcntl_path, F_OK) == 0);
            close(fcntl_dir);
        }

        pid_t fpid = fork();
        if (fpid == 0) {
            if (fchdir(dir_for_fchdir) != 0) _exit(2);
            int child_fd = open(fd_child_file, O_CREAT | O_RDWR, 0644);
            if (child_fd < 0) _exit(3);
            close(child_fd);
            _exit(0);
        } else if (fpid > 0) {
            int fstatus;
            waitpid(fpid, &fstatus, 0);
            CHECK("fork: child inherits fchdir directory fd",
                  WIFEXITED(fstatus) && WEXITSTATUS(fstatus) == 0);
            CHECK("access: fork fchdir file created in directory", access(fd_child_path, F_OK) == 0);
        } else {
            FAIL("fork: fchdir inheritance fork failed");
        }

        unlink(fd_file_path);
        unlink(fd_dup_path);
        unlink(fd_fcntl_path);
        unlink(fd_child_path);
    }
    if (dir_for_fchdir >= 0) close(dir_for_fchdir);
    if (saved_cwd >= 0) close(saved_cwd);
    rmdir(fd_dir_name);

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
