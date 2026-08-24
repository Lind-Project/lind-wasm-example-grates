#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <semaphore.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#include <threei.h>
#include "imfs.h"

const char *preload_files;
const char *dump_files;

static void dump_outputs(const char *env) {
    if (!env || strlen(env) == 0) return;
    char *list = strdup(env);
    if (!list) return;
    char *entry = strtok(list, ";");
    while (entry) {
        while (*entry == ' ' || *entry == '\t') entry++;
        if (strlen(entry) > 0) {
            char *sep = strchr(entry, '=');
            char *imfs_path = entry, *actual_path = entry;
            if (sep) { *sep = '\0'; actual_path = sep + 1; }
            if (strlen(imfs_path) > 0 && strlen(actual_path) > 0) {
                fprintf(stderr, "dumping %s -> %s\n", imfs_path, actual_path);
                dump_file(imfs_path, actual_path);
            }
        }
        entry = strtok(NULL, ";");
    }
    free(list);
}

static inline void sys_log_args(const char *name, unsigned long a1,
                                unsigned long a2, unsigned long a3,
                                unsigned long a4, unsigned long a5,
                                unsigned long a6, long ret) {
    char buf[512]; size_t pos = 0;
    pos += snprintf(buf + pos, sizeof(buf) - pos, "%s (", name);
    unsigned long args[6] = {a1, a2, a3, a4, a5, a6};
    int first = 1;
    for (int i = 0; i < 6; i++) {
        if (args[i] == 0xdeadbeefdeadbeefULL) continue;
        if (!first) pos += snprintf(buf + pos, sizeof(buf) - pos, ", ");
        pos += snprintf(buf + pos, sizeof(buf) - pos, "%lu", args[i]);
        first = 0;
    }
    snprintf(buf + pos, sizeof(buf) - pos, ") = %ld\n", ret);
    fprintf(stderr, "%s", buf);
}

#ifdef DIAG
#define SYS_LOG(name, ret) \
    sys_log_args((name), args[0], args[1], args[2], args[3], args[4], args[5], (ret))
#else
#define SYS_LOG(...) ((void)0)
#endif

/* ---- handlers: current ABI (pid_t cageid, const int arg_cage[6],
 *                              unsigned long args[6]) ---- */

/*
 * openat(dirfd, pathname, flags, mode):
 *   args[0]=dirfd  args[1]=pathname ptr(cage)  args[2]=flags  args[3]=mode
 * NOTE: this intercepts __NR_openat, so args[0] is the DIRFD (AT_FDCWD=-100),
 * NOT the path. The path pointer is args[1]. (The lind ABI used open(path,...)
 * numbering; openat shifts everything by one and adds dirfd.)
 */
long open_grate(pid_t cageid, const int arg_cage[6], unsigned long args[6]) {
    pid_t thiscage = getpid();
    int   dirfd    = (int)args[0];
    /* the path pointer belongs to arg_cage[1]; 0 means the calling cage */
    pid_t path_cage = arg_cage[1] ? arg_cage[1] : cageid;
    char *pathname = malloc(256);
    if (!pathname) { perror("malloc"); exit(EXIT_FAILURE); }

    /* copy the pathname (args[1]) from the cage into the grate */
    long cret = copy_data_between_cages(path_cage, args[1], thiscage,
                                        (unsigned long)pathname, 256, 1);
    if (cret < 0) {           /* bad/unmapped cage path -> fail the open,
                               * do NOT feed garbage to imfs_openat */
        free(pathname);
        return -EFAULT;
    }

    /* pass the real dirfd through so AT_FDCWD is handled by imfs, not indexed */
    int ifd = imfs_openat(cageid, dirfd, pathname, (int)args[2], (mode_t)args[3]);
    SYS_LOG("OPEN", ifd);
    free(pathname);
    return ifd;
}

/* fcntl(fd, cmd, arg): args[0]=fd, args[1]=cmd, args[2]=arg */
long fcntl_grate(pid_t cageid, const int arg_cage[6], unsigned long args[6]) {
    (void)arg_cage;
    long ret = imfs_fcntl(cageid, args[0], args[1], args[2]);
    SYS_LOG("FCNTL", ret);
    return ret;
}

/* unlink(path): args[0]=path ptr(cage) */
long unlink_grate(pid_t cageid, const int arg_cage[6], unsigned long args[6]) {
    pid_t thiscage = getpid();
    pid_t path_cage = arg_cage[0] ? arg_cage[0] : cageid;
    char *pathname = malloc(256);
    if (!pathname) { perror("malloc"); exit(EXIT_FAILURE); }
    copy_data_between_cages(path_cage, args[0], thiscage,
                            (unsigned long)pathname, 256);
    long ret = imfs_unlink(cageid, pathname);
    SYS_LOG("UNLINK", ret);
    free(pathname);
    return ret;
}

/* close(fd): args[0]=fd */
long close_grate(pid_t cageid, const int arg_cage[6], unsigned long args[6]) {
    (void)arg_cage;
    long ret = imfs_close(cageid, args[0]);
    SYS_LOG("CLOSE", ret);
    return ret;
}

/* lseek(fd, offset, whence): args[0]=fd, args[1]=offset, args[2]=whence */
long lseek_grate(pid_t cageid, const int arg_cage[6], unsigned long args[6]) {
    (void)arg_cage;
    off_t ret = imfs_lseek(cageid, (int)args[0], (off_t)args[1], (int)args[2]);
    SYS_LOG("LSEEK", ret);
    return ret;
}

/* read(fd, buf, count): args[0]=fd, args[1]=buf ptr(cage), args[2]=count.
 * Read fills the grate buffer, then copies OUT to the cage's buf. */
long read_grate(pid_t cageid, const int arg_cage[6], unsigned long args[6]) {
    pid_t thiscage = getpid();
    pid_t buf_cage = arg_cage[1] ? arg_cage[1] : cageid;
    size_t count = (size_t)args[2];
    char *buf = malloc(count);
    if (!buf) { fprintf(stderr, "malloc failed\n"); exit(1); }

    ssize_t ret = imfs_read(cageid, args[0], buf, count);
    if (args[1] != 0)      /* skip copy-back on NULL user buffer */
        copy_data_between_cages(thiscage, (unsigned long)buf,
                                buf_cage, args[1], count);
    SYS_LOG("READ", ret);
    free(buf);
    return ret;
}

/* pread(fd, buf, count, offset): args[3]=offset */
long pread_grate(pid_t cageid, const int arg_cage[6], unsigned long args[6]) {
    pid_t thiscage = getpid();
    pid_t buf_cage = arg_cage[1] ? arg_cage[1] : cageid;
    size_t count = (size_t)args[2];
    char *buf = malloc(count);
    if (!buf) { fprintf(stderr, "malloc failed\n"); exit(1); }

    ssize_t ret = imfs_pread(cageid, args[0], buf, count, args[3]);
    if (args[1] != 0)
        copy_data_between_cages(thiscage, (unsigned long)buf,
                                buf_cage, args[1], count);
    SYS_LOG("PREAD", ret);
    free(buf);
    return ret;
}

/* write(fd, buf, count): copies IN from the cage's buf, then imfs_write */
long write_grate(pid_t cageid, const int arg_cage[6], unsigned long args[6]) {
    pid_t thiscage = getpid();
    pid_t buf_cage = arg_cage[1] ? arg_cage[1] : cageid;
    size_t count = (size_t)args[2];
    char *buffer = malloc(count);
    if (!buffer) { perror("malloc"); exit(1); }

    copy_data_between_cages(buf_cage, args[1], thiscage,
                            (unsigned long)buffer, count);

    long ret;
    if (args[0] < 3) {                 /* stdio passthrough */
        ret = write((int)args[0], buffer, count);
    } else {
        ret = imfs_write(cageid, args[0], buffer, count);
    }
    SYS_LOG("WRITE", ret);
    free(buffer);
    return ret;
}

/* pwrite(fd, buf, count, offset): args[3]=offset */
long pwrite_grate(pid_t cageid, const int arg_cage[6], unsigned long args[6]) {
    pid_t thiscage = getpid();
    pid_t buf_cage = arg_cage[1] ? arg_cage[1] : cageid;
    size_t count = (size_t)args[2];
    char *buffer = malloc(count);
    if (!buffer) { perror("malloc"); exit(1); }

    copy_data_between_cages(buf_cage, args[1], thiscage,
                            (unsigned long)buffer, count);

    long ret;
    if (args[0] < 3) {
        ret = write((int)args[0], buffer, count);
    } else {
        ret = imfs_pwrite(cageid, args[0], buffer, count, args[3]);
    }
    SYS_LOG("PWRITE", ret);
    free(buffer);
    return ret;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <cage_file>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    sem_t *sem = mmap(NULL, sizeof(*sem), PROT_READ | PROT_WRITE,
                      MAP_SHARED | MAP_ANON, -1, 0);
    sem_init(sem, 1, 0);

    pid_t grateid = getpid();
    imfs_init();
    preload_files = getenv("PRELOADS");
    preloads(preload_files);

    pid_t cageid = fork();
    if (cageid < 0) { perror("fork"); exit(EXIT_FAILURE); }
    if (cageid == 0) {
        sem_wait(sem);                 /* wait until the grate registers */
        if (execv(argv[1], &argv[1]) == -1) { perror("execv"); exit(EXIT_FAILURE); }
    }

    /* register handlers by __NR_* (was raw numbers). open() -> __NR_openat on
     * x86-64 glibc, so register openat; also register __NR_open if the cage
     * might issue it directly. */
    register_handler(cageid, __NR_openat, grateid, (unsigned long)&open_grate);
#ifdef __NR_open
    register_handler(cageid, __NR_open,   grateid, (unsigned long)&open_grate);
#endif
    register_handler(cageid, __NR_lseek,  grateid, (unsigned long)&lseek_grate);
    register_handler(cageid, __NR_read,   grateid, (unsigned long)&read_grate);
    register_handler(cageid, __NR_write,  grateid, (unsigned long)&write_grate);
    register_handler(cageid, __NR_close,  grateid, (unsigned long)&close_grate);
    register_handler(cageid, __NR_fcntl,  grateid, (unsigned long)&fcntl_grate);
    register_handler(cageid, __NR_unlink, grateid, (unsigned long)&unlink_grate);
    register_handler(cageid, __NR_pread64,  grateid, (unsigned long)&pread_grate);
    register_handler(cageid, __NR_pwrite64, grateid, (unsigned long)&pwrite_grate);

    sem_post(sem);                     /* let the cage exec */

    int status, w;
    while (1) { w = wait(&status); if (w > 0) break; }

    dump_files = getenv("DUMPS");
    dump_outputs(dump_files);

    sem_destroy(sem);
    munmap(sem, sizeof(*sem));
}
