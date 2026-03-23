#include <errno.h>
#include <lind_syscall.h>

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define SYS_READ    0
#define SYS_WRITE   1
#define SYS_EXECVE  59
#define SYS_OPENAT  257

#define MAX_PATH_LEN 512
#define MAX_PREVIEW  64

static FILE *witness_log = NULL;

/* ---------------- logging ---------------- */

static void init_witness_log(void) {
    if (witness_log != NULL) {
        return;
    }

    const char *path = getenv("WITNESS_LOG");
    if (path == NULL) {
        path = "/tmp/witness.log";
    }

    witness_log = fopen(path, "a");
    if (witness_log == NULL) {
        perror("[WitnessGrate] fopen");
        assert(0);
    }

    fprintf(witness_log, "=== witness grate start grate_pid=%d ===\n", getpid());
    fflush(witness_log);
}

static void log_line(const char *line) {
    init_witness_log();
    fprintf(witness_log, "%s\n", line);
    fflush(witness_log);
}

/* ---------------- dispatcher ---------------- */

int pass_fptr_to_wt(uint64_t fn_ptr_uint, uint64_t cageid, uint64_t arg1,
                    uint64_t arg1cage, uint64_t arg2, uint64_t arg2cage,
                    uint64_t arg3, uint64_t arg3cage, uint64_t arg4,
                    uint64_t arg4cage, uint64_t arg5, uint64_t arg5cage,
                    uint64_t arg6, uint64_t arg6cage) {
    if (fn_ptr_uint == 0) {
        fprintf(stderr, "[WitnessGrate] Invalid function ptr\n");
        assert(0);
    }

    int (*fn)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
              uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
              uint64_t, uint64_t, uint64_t) =
        (int (*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                 uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                 uint64_t, uint64_t, uint64_t))(uintptr_t)fn_ptr_uint;

    return fn(cageid, arg1, arg1cage, arg2, arg2cage,
              arg3, arg3cage, arg4, arg4cage,
              arg5, arg5cage, arg6, arg6cage);
}

/* ---------------- shared forwarding ---------------- */

static int forward_syscall(uint64_t syscallno,
                           uint64_t cageid,
                           uint64_t arg1, uint64_t arg1cage,
                           uint64_t arg2, uint64_t arg2cage,
                           uint64_t arg3, uint64_t arg3cage,
                           uint64_t arg4, uint64_t arg4cage,
                           uint64_t arg5, uint64_t arg5cage,
                           uint64_t arg6, uint64_t arg6cage) {
    int self_grate_id = getpid();

    return make_threei_call(
        syscallno,
        0,              // callname unused
        self_grate_id,  // grate cage
        arg1cage,       // target cage
        arg1, arg1cage,
        arg2, arg2cage,
        arg3, arg3cage,
        arg4, arg4cage,
        arg5, arg5cage,
        arg6, arg6cage,
        0               // raw errno
    );
}

/* ---------------- helpers ---------------- */

/*
 * Copy a NULL-terminated string from caller cage memory into the grate.
 *
 * src_ptr: pointer in src_cage's address space
 * src_cage: cage that owns the source memory
 *
 * Returns 0 on success, -1 on failure.
 */
static int copy_cstr_from_cage(uint64_t src_ptr, uint64_t src_cage,
                               char *dst, size_t dst_len) {
    if (dst == NULL || dst_len == 0) {
        return -1;
    }

    memset(dst, 0, dst_len);

    int self_grate_id = getpid();

    int ret = copy_data_between_cages(
        self_grate_id,          // thiscage (caller = grate)
        self_grate_id,          // targetcage
        src_ptr,                // srcaddr in source cage
        src_cage,               // srccage
        (uint64_t)(uintptr_t)dst,
        self_grate_id,          // dest buffer belongs to grate
        dst_len - 1,            // leave room for NUL
        1                       // string copy
    );

    if (ret < 0) {
        dst[0] = '\0';
        return -1;
    }

    dst[dst_len - 1] = '\0';
    return 0;
}

/*
 * Copy up to max_len bytes from caller cage into local buffer.
 * Used for read/write previews.
 */
static int copy_bytes_from_cage(uint64_t src_ptr, uint64_t src_cage,
                                void *dst, size_t max_len) {
    if (dst == NULL || max_len == 0) {
        return -1;
    }

    int self_grate_id = getpid();

    return copy_data_between_cages(
        self_grate_id,
        self_grate_id,
        src_ptr,
        src_cage,
        (uint64_t)(uintptr_t)dst,
        self_grate_id,
        max_len,
        0   // normal copy
    );
}

static void render_preview(const unsigned char *buf, size_t len,
                           char *out, size_t out_len) {
    size_t i;
    size_t pos = 0;

    if (out_len == 0) {
        return;
    }

    out[0] = '\0';

    for (i = 0; i < len; i++) {
        unsigned char c = buf[i];
        char tmp[5];

        if (c >= 32 && c <= 126 && c != '\\' && c != '"') {
            tmp[0] = (char)c;
            tmp[1] = '\0';
        } else {
            snprintf(tmp, sizeof(tmp), "\\x%02x", c);
        }

        size_t need = strlen(tmp);
        if (pos + need + 1 >= out_len) {
            break;
        }

        memcpy(out + pos, tmp, need);
        pos += need;
        out[pos] = '\0';
    }
}

static void safe_copy_path_or_placeholder(uint64_t ptr, uint64_t cage,
                                          char *buf, size_t buflen) {
    if (copy_cstr_from_cage(ptr, cage, buf, buflen) < 0 || buf[0] == '\0') {
        snprintf(buf, buflen, "<unresolved ptr=%llu cage=%llu>",
                 (unsigned long long)ptr,
                 (unsigned long long)cage);
    }
}

/* ---------------- witness handlers ---------------- */

/* execve(filename, argv, envp) */
int execve_witness(uint64_t cageid,
                   uint64_t arg1, uint64_t arg1cage,
                   uint64_t arg2, uint64_t arg2cage,
                   uint64_t arg3, uint64_t arg3cage,
                   uint64_t arg4, uint64_t arg4cage,
                   uint64_t arg5, uint64_t arg5cage,
                   uint64_t arg6, uint64_t arg6cage) {
    char filebuf[MAX_PATH_LEN];
    char logbuf[1024];

    safe_copy_path_or_placeholder(arg1, arg1cage, filebuf, sizeof(filebuf));

    snprintf(logbuf, sizeof(logbuf),
             "[WitnessGrate] BEFORE execve cage=%llu file=\"%s\" argv_ptr=%llu argv_cage=%llu",
             (unsigned long long)cageid,
             filebuf,
             (unsigned long long)arg2,
             (unsigned long long)arg2cage);
    log_line(logbuf);

    int ret = forward_syscall(
        SYS_EXECVE, cageid,
        arg1, arg1cage,
        arg2, arg2cage,
        arg3, arg3cage,
        arg4, arg4cage,
        arg5, arg5cage,
        arg6, arg6cage
    );

    snprintf(logbuf, sizeof(logbuf),
             "[WitnessGrate] AFTER execve cage=%llu file=\"%s\" ret=%d",
             (unsigned long long)cageid,
             filebuf,
             ret);
    log_line(logbuf);

    return ret;
}

/* openat(dirfd, pathname, flags, mode) */
int openat_witness(uint64_t cageid,
                   uint64_t arg1, uint64_t arg1cage,
                   uint64_t arg2, uint64_t arg2cage,
                   uint64_t arg3, uint64_t arg3cage,
                   uint64_t arg4, uint64_t arg4cage,
                   uint64_t arg5, uint64_t arg5cage,
                   uint64_t arg6, uint64_t arg6cage) {
    char pathbuf[MAX_PATH_LEN];
    char logbuf[1024];

    safe_copy_path_or_placeholder(arg2, arg2cage, pathbuf, sizeof(pathbuf));

    snprintf(logbuf, sizeof(logbuf),
             "[WitnessGrate] BEFORE openat cage=%llu dirfd=%lld path=\"%s\" flags=%llu mode=%llu",
             (unsigned long long)cageid,
             (long long)arg1,
             pathbuf,
             (unsigned long long)arg3,
             (unsigned long long)arg4);
    log_line(logbuf);

    int ret = forward_syscall(
        SYS_OPENAT, cageid,
        arg1, arg1cage,
        arg2, arg2cage,
        arg3, arg3cage,
        arg4, arg4cage,
        arg5, arg5cage,
        arg6, arg6cage
    );

    snprintf(logbuf, sizeof(logbuf),
             "[WitnessGrate] AFTER openat cage=%llu path=\"%s\" ret=%d",
             (unsigned long long)cageid,
             pathbuf,
             ret);
    log_line(logbuf);

    return ret;
}

/* read(fd, buf, count) */
int read_witness(uint64_t cageid,
                 uint64_t arg1, uint64_t arg1cage,
                 uint64_t arg2, uint64_t arg2cage,
                 uint64_t arg3, uint64_t arg3cage,
                 uint64_t arg4, uint64_t arg4cage,
                 uint64_t arg5, uint64_t arg5cage,
                 uint64_t arg6, uint64_t arg6cage) {
    char logbuf[1024];

    snprintf(logbuf, sizeof(logbuf),
             "[WitnessGrate] BEFORE read cage=%llu fd=%lld count=%llu buf_ptr=%llu buf_cage=%llu",
             (unsigned long long)cageid,
             (long long)arg1,
             (unsigned long long)arg3,
             (unsigned long long)arg2,
             (unsigned long long)arg2cage);
    log_line(logbuf);

    int ret = forward_syscall(
        SYS_READ, cageid,
        arg1, arg1cage,
        arg2, arg2cage,
        arg3, arg3cage,
        arg4, arg4cage,
        arg5, arg5cage,
        arg6, arg6cage
    );

    if (ret > 0) {
        unsigned char preview[MAX_PREVIEW];
        char rendered[4 * MAX_PREVIEW + 1];
        size_t copy_len = (ret < MAX_PREVIEW) ? (size_t)ret : (size_t)MAX_PREVIEW;

        memset(preview, 0, sizeof(preview));
        rendered[0] = '\0';

        if (copy_bytes_from_cage(arg2, arg2cage, preview, copy_len) >= 0) {
            render_preview(preview, copy_len, rendered, sizeof(rendered));
            snprintf(logbuf, sizeof(logbuf),
                     "[WitnessGrate] AFTER read cage=%llu fd=%lld ret=%d preview=\"%s\"",
                     (unsigned long long)cageid,
                     (long long)arg1,
                     ret,
                     rendered);
        } else {
            snprintf(logbuf, sizeof(logbuf),
                     "[WitnessGrate] AFTER read cage=%llu fd=%lld ret=%d preview=<copy-failed>",
                     (unsigned long long)cageid,
                     (long long)arg1,
                     ret);
        }
    } else {
        snprintf(logbuf, sizeof(logbuf),
                 "[WitnessGrate] AFTER read cage=%llu fd=%lld ret=%d",
                 (unsigned long long)cageid,
                 (long long)arg1,
                 ret);
    }

    log_line(logbuf);
    return ret;
}

/* write(fd, buf, count) */
int write_witness(uint64_t cageid,
                  uint64_t arg1, uint64_t arg1cage,
                  uint64_t arg2, uint64_t arg2cage,
                  uint64_t arg3, uint64_t arg3cage,
                  uint64_t arg4, uint64_t arg4cage,
                  uint64_t arg5, uint64_t arg5cage,
                  uint64_t arg6, uint64_t arg6cage) {
    char logbuf[1024];
    unsigned char preview[MAX_PREVIEW];
    char rendered[4 * MAX_PREVIEW + 1];
    size_t copy_len = (arg3 < MAX_PREVIEW) ? (size_t)arg3 : (size_t)MAX_PREVIEW;

    rendered[0] = '\0';

    if (copy_len > 0 && copy_bytes_from_cage(arg2, arg2cage, preview, copy_len) >= 0) {
        render_preview(preview, copy_len, rendered, sizeof(rendered));
        snprintf(logbuf, sizeof(logbuf),
                 "[WitnessGrate] BEFORE write cage=%llu fd=%lld count=%llu preview=\"%s\"",
                 (unsigned long long)cageid,
                 (long long)arg1,
                 (unsigned long long)arg3,
                 rendered);
    } else {
        snprintf(logbuf, sizeof(logbuf),
                 "[WitnessGrate] BEFORE write cage=%llu fd=%lld count=%llu preview=<unavailable>",
                 (unsigned long long)cageid,
                 (long long)arg1,
                 (unsigned long long)arg3);
    }
    log_line(logbuf);

    int ret = forward_syscall(
        SYS_WRITE, cageid,
        arg1, arg1cage,
        arg2, arg2cage,
        arg3, arg3cage,
        arg4, arg4cage,
        arg5, arg5cage,
        arg6, arg6cage
    );

    snprintf(logbuf, sizeof(logbuf),
             "[WitnessGrate] AFTER write cage=%llu fd=%lld count=%llu ret=%d",
             (unsigned long long)cageid,
             (long long)arg1,
             (unsigned long long)arg3,
             ret);
    log_line(logbuf);

    return ret;
}

/* ---------------- registration ---------------- */

static void register_witness_handlers(int cageid, int grateid) {
    uint64_t execve_ptr = (uint64_t)(uintptr_t)&execve_witness;
    uint64_t openat_ptr = (uint64_t)(uintptr_t)&openat_witness;
    uint64_t read_ptr   = (uint64_t)(uintptr_t)&read_witness;
    uint64_t write_ptr  = (uint64_t)(uintptr_t)&write_witness;

    int ret;

    ret = register_handler(cageid, SYS_EXECVE, grateid, execve_ptr);
    if (ret != 0) {
        fprintf(stderr, "[WitnessGrate] register execve failed ret=%d\n", ret);
        assert(0);
    }

    ret = register_handler(cageid, SYS_OPENAT, grateid, openat_ptr);
    if (ret != 0) {
        fprintf(stderr, "[WitnessGrate] register openat failed ret=%d\n", ret);
        assert(0);
    }

    ret = register_handler(cageid, SYS_READ, grateid, read_ptr);
    if (ret != 0) {
        fprintf(stderr, "[WitnessGrate] register read failed ret=%d\n", ret);
        assert(0);
    }

    ret = register_handler(cageid, SYS_WRITE, grateid, write_ptr);
    if (ret != 0) {
        fprintf(stderr, "[WitnessGrate] register write failed ret=%d\n", ret);
        assert(0);
    }

    printf("[WitnessGrate] Registered handlers for cage=%d via grate=%d\n",
           cageid, grateid);
}

/* ---------------- main ---------------- */

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <target_program> [target args...]\n", argv[0]);
        assert(0);
    }

    init_witness_log();

    int grateid = getpid();
    printf("[WitnessGrate] Start grate pid=%d\n", grateid);

    pid_t pid = fork();
    if (pid < 0) {
        perror("[WitnessGrate] fork failed");
        assert(0);
    } else if (pid == 0) {
        int cageid = getpid();

        printf("[WitnessGrate] Child cage=%d registering handlers with grate=%d\n",
               cageid, grateid);

        register_witness_handlers(cageid, grateid);

        if (execv(argv[1], &argv[1]) == -1) {
            perror("[WitnessGrate] execv failed");
            assert(0);
        }
    }

    int status;
    while (wait(&status) > 0) {
        if (status != 0) {
            fprintf(stderr, "[WitnessGrate] FAIL: child exited with status %d\n", status);
            assert(0);
        }
    }

    log_line("=== witness grate finished successfully ===");
    printf("[WitnessGrate] PASS\n");
    return 0;
}
