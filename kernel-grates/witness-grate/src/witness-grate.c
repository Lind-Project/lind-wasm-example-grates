#define _GNU_SOURCE
#include <assert.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "threei.h"
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
 * Shared forwarding
 * ============================================================ */

/*
 * Forward the intercepted syscall to the kernel on the cage's behalf. Passing
 * primary_cage = cage with the handler's own arg_cage/args makes the kernel
 * stage the cage's pointer arguments and run the real syscall; it does not
 * re-dispatch to this handler. make_threei_call returns the kernel's raw result
 * (including -errno), which we hand straight back to the cage.
 */
static long forward_syscall(uint64_t syscallno, pid_t cage,
			    const int arg_cage[6], unsigned long args[6]) {
	return make_threei_call((unsigned int)syscallno, cage, arg_cage, args);
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

static long signed_forward(uint64_t syscallno, pid_t cage,
			   const int arg_cage[6], unsigned long args[6]) {
	witness_ctx_t *ctx = get_or_create_witness_ctx((uint64_t)cage);
	syscall_record_t rec;
	uint8_t sig[SIG_LEN];
	int i;

	memset(&rec, 0, sizeof(rec));

	pthread_mutex_lock(&ctx->lock);

	rec.seqno = ctx->seqno++;
	rec.syscallno = syscallno;
	rec.cageid = (uint64_t)cage;

	for (i = 0; i < 6; i++) {
		rec.args[i] = args[i];
		rec.arg_cages[i] = (uint64_t)arg_cage[i];
	}

	if (sign_record_detached(&rec, ctx->pubkey, ctx->privkey, sig) != 0) {
		pthread_mutex_unlock(&ctx->lock);
		fprintf(stderr, "[WitnessGrate] sign_record_detached failed\n");
		assert(0);
	}

	pthread_mutex_unlock(&ctx->lock);

	emit_signed_record(&rec, sig);

	return forward_syscall(syscallno, cage, arg_cage, args);
}

/* ============================================================
 * Witness handlers (3i ABI)
 * ============================================================ */

long execve_witness(pid_t cage, const int arg_cage[6], unsigned long args[6]) {
	return signed_forward(SYS_EXECVE, cage, arg_cage, args);
}

long openat_witness(pid_t cage, const int arg_cage[6], unsigned long args[6]) {
	return signed_forward(SYS_OPENAT, cage, arg_cage, args);
}

long read_witness(pid_t cage, const int arg_cage[6], unsigned long args[6]) {
	return signed_forward(SYS_READ, cage, arg_cage, args);
}

long write_witness(pid_t cage, const int arg_cage[6], unsigned long args[6]) {
	return signed_forward(SYS_WRITE, cage, arg_cage, args);
}

/* ============================================================
 * Registration
 * ============================================================ */

static void register_witness_handlers(int cageid, int grateid) {
	struct {
		unsigned int nr;
		threei_handler_fn fn;
		const char *name;
	} tbl[] = {
		{ SYS_EXECVE, execve_witness, "execve" },
		{ SYS_OPENAT, openat_witness, "openat" },
		{ SYS_READ,   read_witness,   "read"   },
		{ SYS_WRITE,  write_witness,  "write"  },
	};

	for (size_t i = 0; i < sizeof(tbl) / sizeof(tbl[0]); i++) {
		int ret = register_handler(cageid, tbl[i].nr, grateid,
					   (unsigned long)tbl[i].fn);
		if (ret != 0) {
			fprintf(stderr, "[WitnessGrate] register %s failed ret=%d\n",
				tbl[i].name, ret);
			assert(0);
		}
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

	pid = fork();
	if (pid < 0) {
		perror("[WitnessGrate] fork failed");
		assert(0);
	}

	if (pid == 0) {
		/*
		 * Child: register the witness handlers for this (soon-to-be)
		 * cage, then exec the target. Registering before execv means
		 * the handlers are active the instant the cage runs -- no setup
		 * semaphore. The grate services (signs + forwards) from the
		 * parent via the 3i runtime threads.
		 */
		register_witness_handlers(getpid(), grateid);

		if (execv(argv[1], &argv[1]) == -1) {
			perror("[WitnessGrate] execv failed");
			_exit(127);
		}
		_exit(127);
	}

	/*
	 * Parent: pre-generate this cage's keypair and emit its PUBKEY up front
	 * (signed_forward would otherwise create it lazily on the first call).
	 */
	(void)get_or_create_witness_ctx((uint64_t)pid);
	log_line_to_file("=== witness keypair generated for cage ===");

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

	log_line_to_file("=== witness grate finished successfully ===");
	debug_printf("[WitnessGrate] PASS\n");
	return 0;
}
