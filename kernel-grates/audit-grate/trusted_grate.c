#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <threei.h>

#define LOG(...) fprintf(stderr, "[audit] " __VA_ARGS__)

#define BLOCKED_PATH "/etc/passwd"
#define PATH_BUF_SIZE 4096

static int read_path_from_cage(pid_t owner, unsigned long ptr,
                               char *path, size_t size)
{
    long ret;

    if (owner <= 0 || ptr == 0 || size == 0)
        return -1;

    memset(path, 0, size);

    ret = copy_data_between_cages(owner, ptr, getpid(),
                                  (unsigned long)path, size,
                                  THREEI_COPY_STRNCPY);
    if (ret < 0)
        return -1;

    return 0;
}

/*
 * Handler for make_threei_call (syscall 473).
 *
 * Logs forwarded syscalls and denies open/openat requests whose
 * pathname is exactly BLOCKED_PATH.
 */
long h_make_threei_call(pid_t cageid, const int arg_cage[6],
                        unsigned long args[6])
{
    (void)arg_cage;

    unsigned int nr = (unsigned int)args[0];
    pid_t primary_cage = (pid_t)args[1];
    unsigned long ac_ptr = args[2];
    unsigned long a_ptr = args[3];

    unsigned long fwd_args[6] = {0};
    int fwd_argcage[6] = {0};

    /* Read forwarded syscall arguments from the calling grate. */
    if (a_ptr &&
        copy_data_between_cages(cageid, a_ptr, getpid(),
                                (unsigned long)fwd_args,
                                sizeof(fwd_args),
                                THREEI_COPY_MEMCPY) < 0) {
        LOG("grate %d: cannot read forwarded arguments "
            "(nr=%u, primary=%d)\n",
            (int)cageid, nr, (int)primary_cage);

        return make_threei_call(__NR_make_threei_call,
                                cageid, NULL, args);
    }

    /* Read argument ownership metadata from the calling grate. */
    if (ac_ptr &&
        copy_data_between_cages(cageid, ac_ptr, getpid(),
                                (unsigned long)fwd_argcage,
                                sizeof(fwd_argcage),
                                THREEI_COPY_MEMCPY) < 0) {
        LOG("grate %d: cannot read argument-cage metadata\n",
            (int)cageid);
    }

    /* Identify pathname argument for open/openat. */
    int path_index = -1;
    unsigned long path_ptr = 0;

    if (nr == __NR_open) {
        path_index = 0;
        path_ptr = fwd_args[0];
    }
#ifdef __NR_openat
    else if (nr == __NR_openat) {
        path_index = 1;
        path_ptr = fwd_args[1];
    }
#endif

    /*
     * Read the pathname from its owning address space.
     * A zero arg_cage entry means the pointer belongs to the
     * primary cage; a nonzero entry identifies another owner.
     */
    if (path_index >= 0 && path_ptr) {
        char path[PATH_BUF_SIZE];
        pid_t path_owner = fwd_argcage[path_index];

        if (path_owner <= 0)
            path_owner = primary_cage;

        if (read_path_from_cage(path_owner, path_ptr,
                                path, sizeof(path)) == 0) {
            LOG("syscall nr=%u pathname=%s owner=%d\n",
                nr, path, (int)path_owner);

            if (strcmp(path, BLOCKED_PATH) == 0) {
                LOG("BLOCKED pathname=%s -> EPERM\n", path);
                return -EPERM;
            }
        } else {
            LOG("could not read pathname for syscall nr=%u "
                "(owner=%d, ptr=%#lx)\n",
                nr, (int)path_owner, path_ptr);
        }
    }

    /* Audit the forwarding request. */
    LOG("grate %d -> forward nr=%u for cage %d args=[",
        (int)cageid, nr, (int)primary_cage);

    for (int i = 0; i < 6; i++) {
        fprintf(stderr, "0x%lx%s",
                fwd_args[i], i < 5 ? ", " : "");
    }

    fprintf(stderr, "] arg_cage=[");

    for (int i = 0; i < 6; i++) {
        fprintf(stderr, "%d%s",
                fwd_argcage[i], i < 5 ? "," : "");
    }

    fprintf(stderr, "]\n");

    /*
     * Let the original forwarding grate execute the call.
     * Do not re-forward the underlying syscall ourselves.
     */
    return make_threei_call(__NR_make_threei_call,
                            cageid, NULL, args);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        LOG("usage: %s <grate-program> [args...]\n", argv[0]);
        return 1;
    }

    pid_t auditid = getpid();
    pid_t pid = fork();

    if (pid < 0) {
        perror("fork");
        return 1;
    }

    if (pid == 0) {
        pid_t grateid = getpid();

        if (register_handler(grateid, __NR_make_threei_call,
                             auditid,
                             (unsigned long)h_make_threei_call) < 0) {
            fprintf(stderr, "arm 473 audit failed: %s\n",
                    strerror(errno));
            _exit(1);
        }

        LOG("armed make_threei_call(%d) audit on grate %d\n",
            __NR_make_threei_call, (int)grateid);

        execv(argv[1], &argv[1]);
        perror("execv");
        _exit(1);
    }

    LOG("%d entering receive loop (auditing make_threei_call)\n",
        (int)auditid);

    int status;
    pid_t waited;

    while ((waited = wait(&status)) > 0) {
        if (WIFEXITED(status)) {
            LOG("audited grate exited with status %d\n",
                WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
            LOG("audited grate killed by signal %d\n",
                WTERMSIG(status));
        } else {
            LOG("audited grate exited (unknown)\n");
        }
    }

    if (waited < 0 && errno != ECHILD)
        perror("wait");

    return 0;
}

