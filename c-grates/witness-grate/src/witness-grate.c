#include <errno.h>
#include <lind_syscall.h>

#include <assert.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <semaphore.h>
#include <sys/mman.h>
#include <stdarg.h>

#include "ed25519.h"

#define SYS_READ    0
#define SYS_WRITE   1
#define SYS_EXECVE  59
#define SYS_OPENAT  257

#define SEED_LEN    32
#define PUBKEY_LEN  32
#define PRIVKEY_LEN 64
#define SIG_LEN     64

#define MAX_WITNESS_CAGES 128
#define MAX_PATH_LEN 512

/* ============================================================
 * Global logging
 * ============================================================ */

static FILE *witness_log = NULL;
static pthread_mutex_t witness_log_lock = PTHREAD_MUTEX_INITIALIZER;
static int witness_debug_enabled = 0;

static void debug_printf(const char *fmt, ...) {
    if (!witness_debug_enabled) {
        return;
    }

    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
}

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

static void log_line_to_file(const char *line) {
    pthread_mutex_lock(&witness_log_lock);

    init_witness_log();
    fprintf(witness_log, "%s\n", line);
    fflush(witness_log);

    pthread_mutex_unlock(&witness_log_lock);
}

static void bytes_to_hex(const uint8_t *in, size_t len, char *out, size_t out_len) {
    static const char *hex = "0123456789abcdef";
    size_t i;

    if (out_len < len * 2 + 1) {
        assert(0);
    }

    for (i = 0; i < len; i++) {
        out[2 * i]     = hex[(in[i] >> 4) & 0xf];
        out[2 * i + 1] = hex[in[i] & 0xf];
    }
    out[2 * len] = '\0';
}

/* ============================================================
 * Per-cage witness context
 * ============================================================ */

typedef struct {
    uint64_t cageid;

    uint8_t seed[SEED_LEN];
    uint8_t pubkey[PUBKEY_LEN];
    uint8_t privkey[PRIVKEY_LEN];

    uint64_t seqno;

    pthread_mutex_t lock;
    int initialized;
} witness_ctx_t;

static witness_ctx_t witness_ctxs[MAX_WITNESS_CAGES];
static pthread_mutex_t witness_ctxs_lock = PTHREAD_MUTEX_INITIALIZER;

/* ============================================================
 * Syscall record
 * ============================================================ */

typedef struct {
    uint64_t seqno;
    uint64_t syscallno;
    uint64_t cageid;
    uint64_t args[6];
    uint64_t arg_cages[6];
} syscall_record_t;

/* ============================================================
 * Seed / key handling
 * ============================================================ */

static void build_seed_path_for_cage(uint64_t cageid, char *out, size_t out_len) {
    const char *seed_dir = getenv("WITNESS_SEED_DIR");
    if (seed_dir == NULL) {
        seed_dir = ".";
    }

    int n = snprintf(out, out_len, "%s/witness.%llu.seed",
                     seed_dir, (unsigned long long)cageid);
    if (n < 0 || (size_t)n >= out_len) {
        fprintf(stderr, "[WitnessGrate] seed path too long\n");
        assert(0);
    }
}

static void load_seed_file_exact(const char *path, uint8_t seed[SEED_LEN]) {
    FILE *fp = fopen(path, "rb");
    if (fp == NULL) {
        perror("[WitnessGrate] fopen seed");
        fprintf(stderr, "[WitnessGrate] failed seed path: %s\n", path);
        assert(0);
    }

    size_t n = fread(seed, 1, SEED_LEN, fp);
    fclose(fp);

    if (n != SEED_LEN) {
        fprintf(stderr, "[WitnessGrate] seed file must be exactly %d bytes: %s\n",
                SEED_LEN, path);
        assert(0);
    }
}

/*
 * Preferred behavior:
 *   1. try WITNESS_SEED_DIR/witness.<cageid>.seed
 *   2. fallback to ./witness.seed for compatibility
 */
static void load_seed_for_cage(uint64_t cageid, uint8_t seed[SEED_LEN]) {
    char cage_seed_path[MAX_PATH_LEN];
    build_seed_path_for_cage(cageid, cage_seed_path, sizeof(cage_seed_path));

    FILE *fp = fopen(cage_seed_path, "rb");
    if (fp != NULL) {
        fclose(fp);
        load_seed_file_exact(cage_seed_path, seed);
        return;
    }

    /* compatibility fallback */
    load_seed_file_exact("witness.seed", seed);
}

static void init_witness_keys_for_cage(witness_ctx_t *ctx, uint64_t cageid) {
    memset(ctx->seed, 0, sizeof(ctx->seed));
    memset(ctx->pubkey, 0, sizeof(ctx->pubkey));
    memset(ctx->privkey, 0, sizeof(ctx->privkey));

    load_seed_for_cage(cageid, ctx->seed);
    ed25519_create_keypair(ctx->pubkey, ctx->privkey, ctx->seed);
}

static void emit_public_key_for_cage(uint64_t cageid, const uint8_t pubkey[PUBKEY_LEN]) {
    char pub_hex[PUBKEY_LEN * 2 + 1];
    char line[256];

    bytes_to_hex(pubkey, PUBKEY_LEN, pub_hex, sizeof(pub_hex));
    snprintf(line, sizeof(line), "PUBKEY cage=%llu %s",
             (unsigned long long)cageid, pub_hex);
    log_line_to_file(line);
}

/* ============================================================
 * Witness ctx table management
 * ============================================================ */

static witness_ctx_t *find_witness_ctx_locked(uint64_t cageid) {
    int i;
    for (i = 0; i < MAX_WITNESS_CAGES; i++) {
        if (witness_ctxs[i].initialized && witness_ctxs[i].cageid == cageid) {
            return &witness_ctxs[i];
        }
    }
    return NULL;
}

static witness_ctx_t *alloc_witness_ctx_locked(uint64_t cageid) {
    int i;
    for (i = 0; i < MAX_WITNESS_CAGES; i++) {
        if (!witness_ctxs[i].initialized) {
            witness_ctxs[i].cageid = cageid;
            witness_ctxs[i].seqno = 0;
            if (pthread_mutex_init(&witness_ctxs[i].lock, NULL) != 0) {
                perror("[WitnessGrate] pthread_mutex_init");
                assert(0);
            }
            init_witness_keys_for_cage(&witness_ctxs[i], cageid);
            witness_ctxs[i].initialized = 1;
            emit_public_key_for_cage(cageid, witness_ctxs[i].pubkey);
            return &witness_ctxs[i];
        }
    }

    debug_printf("[WitnessGrate] witness ctx table full\n");
    assert(0);
    return NULL;
}

static witness_ctx_t *get_or_create_witness_ctx(uint64_t cageid) {
    witness_ctx_t *ctx;

    pthread_mutex_lock(&witness_ctxs_lock);

    ctx = find_witness_ctx_locked(cageid);
    if (ctx == NULL) {
        ctx = alloc_witness_ctx_locked(cageid);
    }

    pthread_mutex_unlock(&witness_ctxs_lock);
    return ctx;
}

/* ============================================================
 * Dispatcher
 * ============================================================ */

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

/* ============================================================
 * Shared forwarding
 * ============================================================ */

static int forward_syscall(uint64_t syscallno,
                           uint64_t cageid,
                           uint64_t arg1, uint64_t arg1cage,
                           uint64_t arg2, uint64_t arg2cage,
                           uint64_t arg3, uint64_t arg3cage,
                           uint64_t arg4, uint64_t arg4cage,
                           uint64_t arg5, uint64_t arg5cage,
                           uint64_t arg6, uint64_t arg6cage) {
    int self_grate_id = getpid();

    (void)cageid; /* currently unused by make_threei_call path */

    return make_threei_call(
        syscallno,
        0,
        self_grate_id,
        arg1cage,
        arg1, arg1cage,
        arg2, arg2cage,
        arg3, arg3cage,
        arg4, arg4cage,
        arg5, arg5cage,
        arg6, arg6cage,
        0
    );
}

/* ============================================================
 * Signature backend
 * ============================================================ */

static int sign_record_detached(const syscall_record_t *rec,
                                const uint8_t *pubkey,
                                const uint8_t *privkey,
                                uint8_t sig[SIG_LEN]) {
    ed25519_sign(sig,
                 (const unsigned char *)rec,
                 sizeof(*rec),
                 pubkey,
                 privkey);
    return 0;
}

/* ============================================================
 * Evidence output
 * ============================================================ */

static void emit_signed_record(const syscall_record_t *rec,
                               const uint8_t sig[SIG_LEN]) {
    char sig_hex[SIG_LEN * 2 + 1];
    char line[1024];

    bytes_to_hex(sig, SIG_LEN, sig_hex, sizeof(sig_hex));

    snprintf(line, sizeof(line),
             "SIGNED seq=%llu syscall=%llu cage=%llu "
             "a=[%llu,%llu,%llu,%llu,%llu,%llu] "
             "ac=[%llu,%llu,%llu,%llu,%llu,%llu] sig=%s",
             (unsigned long long)rec->seqno,
             (unsigned long long)rec->syscallno,
             (unsigned long long)rec->cageid,
             (unsigned long long)rec->args[0],
             (unsigned long long)rec->args[1],
             (unsigned long long)rec->args[2],
             (unsigned long long)rec->args[3],
             (unsigned long long)rec->args[4],
             (unsigned long long)rec->args[5],
             (unsigned long long)rec->arg_cages[0],
             (unsigned long long)rec->arg_cages[1],
             (unsigned long long)rec->arg_cages[2],
             (unsigned long long)rec->arg_cages[3],
             (unsigned long long)rec->arg_cages[4],
             (unsigned long long)rec->arg_cages[5],
             sig_hex);

    log_line_to_file(line);
}

/* ============================================================
 * Signed forwarding
 * ============================================================ */

static int signed_forward(uint64_t syscallno,
                          uint64_t cageid,
                          uint64_t arg1, uint64_t arg1cage,
                          uint64_t arg2, uint64_t arg2cage,
                          uint64_t arg3, uint64_t arg3cage,
                          uint64_t arg4, uint64_t arg4cage,
                          uint64_t arg5, uint64_t arg5cage,
                          uint64_t arg6, uint64_t arg6cage) {
    witness_ctx_t *ctx = get_or_create_witness_ctx(cageid);
    syscall_record_t rec;
    uint8_t sig[SIG_LEN];

    memset(&rec, 0, sizeof(rec));

    pthread_mutex_lock(&ctx->lock);

    rec.seqno = ctx->seqno++;
    rec.syscallno = syscallno;
    rec.cageid = cageid;

    rec.args[0] = arg1;
    rec.args[1] = arg2;
    rec.args[2] = arg3;
    rec.args[3] = arg4;
    rec.args[4] = arg5;
    rec.args[5] = arg6;

    rec.arg_cages[0] = arg1cage;
    rec.arg_cages[1] = arg2cage;
    rec.arg_cages[2] = arg3cage;
    rec.arg_cages[3] = arg4cage;
    rec.arg_cages[4] = arg5cage;
    rec.arg_cages[5] = arg6cage;

    if (sign_record_detached(&rec, ctx->pubkey, ctx->privkey, sig) != 0) {
        pthread_mutex_unlock(&ctx->lock);
        fprintf(stderr, "[WitnessGrate] sign_record_detached failed\n");
        assert(0);
    }

    pthread_mutex_unlock(&ctx->lock);

    emit_signed_record(&rec, sig);

    return forward_syscall(
        syscallno, cageid,
        arg1, arg1cage,
        arg2, arg2cage,
        arg3, arg3cage,
        arg4, arg4cage,
        arg5, arg5cage,
        arg6, arg6cage
    );
}

/* ============================================================
 * Witness handlers
 * ============================================================ */

int execve_witness(uint64_t cageid,
                   uint64_t arg1, uint64_t arg1cage,
                   uint64_t arg2, uint64_t arg2cage,
                   uint64_t arg3, uint64_t arg3cage,
                   uint64_t arg4, uint64_t arg4cage,
                   uint64_t arg5, uint64_t arg5cage,
                   uint64_t arg6, uint64_t arg6cage) {
    return signed_forward(SYS_EXECVE, cageid,
                          arg1, arg1cage,
                          arg2, arg2cage,
                          arg3, arg3cage,
                          arg4, arg4cage,
                          arg5, arg5cage,
                          arg6, arg6cage);
}

int openat_witness(uint64_t cageid,
                   uint64_t arg1, uint64_t arg1cage,
                   uint64_t arg2, uint64_t arg2cage,
                   uint64_t arg3, uint64_t arg3cage,
                   uint64_t arg4, uint64_t arg4cage,
                   uint64_t arg5, uint64_t arg5cage,
                   uint64_t arg6, uint64_t arg6cage) {
    return signed_forward(SYS_OPENAT, cageid,
                          arg1, arg1cage,
                          arg2, arg2cage,
                          arg3, arg3cage,
                          arg4, arg4cage,
                          arg5, arg5cage,
                          arg6, arg6cage);
}

int read_witness(uint64_t cageid,
                 uint64_t arg1, uint64_t arg1cage,
                 uint64_t arg2, uint64_t arg2cage,
                 uint64_t arg3, uint64_t arg3cage,
                 uint64_t arg4, uint64_t arg4cage,
                 uint64_t arg5, uint64_t arg5cage,
                 uint64_t arg6, uint64_t arg6cage) {
    return signed_forward(SYS_READ, cageid,
                          arg1, arg1cage,
                          arg2, arg2cage,
                          arg3, arg3cage,
                          arg4, arg4cage,
                          arg5, arg5cage,
                          arg6, arg6cage);
}

int write_witness(uint64_t cageid,
                  uint64_t arg1, uint64_t arg1cage,
                  uint64_t arg2, uint64_t arg2cage,
                  uint64_t arg3, uint64_t arg3cage,
                  uint64_t arg4, uint64_t arg4cage,
                  uint64_t arg5, uint64_t arg5cage,
                  uint64_t arg6, uint64_t arg6cage) {
    return signed_forward(SYS_WRITE, cageid,
                          arg1, arg1cage,
                          arg2, arg2cage,
                          arg3, arg3cage,
                          arg4, arg4cage,
                          arg5, arg5cage,
                          arg6, arg6cage);
}

/* ============================================================
 * Registration
 * ============================================================ */

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

    debug_printf("[WitnessGrate] Registered handlers for cage=%d via grate=%d\n",
           cageid, grateid);
}

/* ============================================================
 * Runtime init
 * ============================================================ */

static void init_witness_runtime(void) {
    memset(witness_ctxs, 0, sizeof(witness_ctxs));
}

/* ============================================================
 * Main
 * ============================================================ */

int main(int argc, char *argv[]) {
    sem_t *start_sem;
    int grateid;
    pid_t pid;
    int status;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <target_program> [target args...]\n", argv[0]);
        assert(0);
    }

    init_witness_log();
    init_witness_runtime();

    grateid = getpid();
    debug_printf("[WitnessGrate] Start grate pid=%d\n", grateid);

    /* shared unnamed semaphore for parent-child sync after fork */
    start_sem = mmap(NULL, sizeof(sem_t),
                     PROT_READ | PROT_WRITE,
                     MAP_SHARED | MAP_ANONYMOUS,
                     -1, 0);
    if (start_sem == MAP_FAILED) {
        perror("[WitnessGrate] mmap failed");
        assert(0);
    }

    if (sem_init(start_sem, 1, 0) != 0) {
        perror("[WitnessGrate] sem_init failed");
        assert(0);
    }

    pid = fork();
    if (pid < 0) {
        perror("[WitnessGrate] fork failed");
        assert(0);
    }

    if (pid == 0) {
        /* child: wait until parent finishes ctx init + registration */
        if (sem_wait(start_sem) != 0) {
            perror("[WitnessGrate] child sem_wait failed");
            assert(0);
        }

        if (execv(argv[1], &argv[1]) == -1) {
            perror("[WitnessGrate] execv failed");
            assert(0);
        }

        assert(0);
    }

    /* parent: initialize per-cage witness state and register handlers */
    {
        int cageid = pid;

        debug_printf("[WitnessGrate] Parent preparing child cage=%d with grate=%d\n",
               cageid, grateid);

        (void)get_or_create_witness_ctx((uint64_t)cageid);
        log_line_to_file("=== witness keypair generated for cage ===");

        register_witness_handlers(cageid, grateid);

        if (sem_post(start_sem) != 0) {
            perror("[WitnessGrate] parent sem_post failed");
            assert(0);
        }
    }

    while (wait(&status) > 0) {
        if (status != 0) {
            int exit_code = (status >> 8) & 0xff;

            if (exit_code == 0) {
                exit_code = 1;
            }

            debug_printf(
                    "[WitnessGrate] FAIL: child exited with code %d, raw status %d\n",
                    exit_code, status);

            exit(exit_code);
        }
    }

    if (sem_destroy(start_sem) != 0) {
        perror("[WitnessGrate] sem_destroy failed");
        assert(0);
    }

    munmap(start_sem, sizeof(sem_t));

    log_line_to_file("=== witness grate finished successfully ===");
    debug_printf("[WitnessGrate] PASS\n");
    return 0;
}
