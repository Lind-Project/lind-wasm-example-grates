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

#include "ed25519.h"

#define SYS_READ    0
#define SYS_WRITE   1
#define SYS_EXECVE  59
#define SYS_OPENAT  257

#define SEED_LEN    32
#define PUBKEY_LEN  32
#define PRIVKEY_LEN 64
#define SIG_LEN     64

static FILE *witness_log = NULL;
static uint8_t witness_seed[SEED_LEN];
static uint8_t witness_pubkey[PUBKEY_LEN];
static uint8_t witness_privkey[PRIVKEY_LEN];
static uint64_t witness_seqno = 0;

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

/* ---------------- keygen ---------------- */

static void load_seed_from_file(const char *path) {
    FILE *fp = fopen(path, "rb");
    if (fp == NULL) {
        perror("[WitnessGrate] fopen seed");
        assert(0);
    }

    size_t n = fread(witness_seed, 1, SEED_LEN, fp);
    fclose(fp);

    if (n != SEED_LEN) {
        fprintf(stderr, "[WitnessGrate] seed file must be exactly %d bytes\n", SEED_LEN);
        assert(0);
    }
}

static void init_witness_keys(void) {
    const char *seed_path = "witness.seed";

    load_seed_from_file(seed_path);
    ed25519_create_keypair(witness_pubkey, witness_privkey, witness_seed);
}

static void emit_public_key(void) {
    char pub_hex[PUBKEY_LEN * 2 + 1];
    char line[256];

    bytes_to_hex(witness_pubkey, PUBKEY_LEN, pub_hex, sizeof(pub_hex));
    snprintf(line, sizeof(line), "PUBKEY %s", pub_hex);
    log_line(line);
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

/* ---------------- syscall record ---------------- */

typedef struct {
    uint64_t seqno;
    uint64_t syscallno;
    uint64_t cageid;
    uint64_t args[6];
    uint64_t arg_cages[6];
} syscall_record_t;

/* ---------------- signature backend ---------------- */

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

/* ---------------- evidence output ---------------- */

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

    log_line(line);
}

/* ---------------- signed forwarding ---------------- */

static int signed_forward(uint64_t syscallno,
                          uint64_t cageid,
                          uint64_t arg1, uint64_t arg1cage,
                          uint64_t arg2, uint64_t arg2cage,
                          uint64_t arg3, uint64_t arg3cage,
                          uint64_t arg4, uint64_t arg4cage,
                          uint64_t arg5, uint64_t arg5cage,
                          uint64_t arg6, uint64_t arg6cage) {
    syscall_record_t rec;
    uint8_t sig[SIG_LEN];

    memset(&rec, 0, sizeof(rec));
    rec.seqno = witness_seqno++;
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

    if (sign_record_detached(&rec, witness_pubkey, witness_privkey, sig) != 0) {
        fprintf(stderr, "[WitnessGrate] sign_record_detached failed\n");
        assert(0);
    }

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

/* ---------------- witness handlers ---------------- */

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

    init_witness_keys();
    emit_public_key();
    log_line("=== witness keypair generated ===");

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
