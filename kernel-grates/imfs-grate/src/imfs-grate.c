#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "threei.h"
#include "imfs.h"

/* Stores list of files on host that need to be copied in / out of the IMFS. */
const char *preload_files;
const char *dump_files;

/*
 * Map a 3i cage identity (the cage's real PID, as delivered in the handler's
 * `cage` argument) to a small dense IMFS cage index in [0, MAX_PROCS).
 *
 * IMFS keys its per-cage FD tables (g_fdtable[MAX_PROCS][...]) by a small
 * index, whereas 3i hands us the cage's PID. Using the PID directly indexes
 * far past the table and reads a garbage FileDesc. First cage seen gets index
 * 0, which matches the index preloads() uses to populate the tree. The lock
 * keeps the recv and ring servicing threads from racing on the table.
 *
 * NB: the PID stays the IN/OUT cage for copy_data_between_cages (the kernel
 * copies by PID); only the IMFS library argument is the mapped index.
 */
static int cage_index(pid_t pid) {
	static pid_t map[MAX_PROCS];
	static int count;
	static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
	int idx = 0;

	pthread_mutex_lock(&lock);
	for (int i = 0; i < count; i++) {
		if (map[i] == pid) {
			idx = i;
			goto out;
		}
	}
	if (count < MAX_PROCS) {
		map[count] = pid;
		idx = count++;
	}
out:
	pthread_mutex_unlock(&lock);
	return idx;
}

/*
 * Resolve the cage that actually owns pointer argument `i`. The kernel's
 * convention (threei syscall.c) is that arg_cage[i] <= 0 or arg_cage[i] ==
 * primary means the pointer lives in the primary (calling) cage; a positive,
 * different value means a transient grate remapped it into that cage. So for a
 * normal direct cage syscall arg_cage[] is all zeros and the owner is `cage`.
 */
static inline pid_t arg_owner(const int ac[6], int i, pid_t cage) {
	return (ac[i] <= 0 || ac[i] == cage) ? cage : (pid_t)ac[i];
}

static void dump_outputs(const char *env) {
	if (!env || strlen(env) == 0)
		return;

	char *list = strdup(env);
	if (!list)
		return;

	char *entry = strtok(list, ";");
	while (entry) {
		while (*entry == ' ' || *entry == '\t')
			entry++;

		if (strlen(entry) > 0) {
			char *sep = strchr(entry, '=');
			char *imfs_path = entry;
			char *actual_path = entry;

			if (sep) {
				*sep = '\0';
				actual_path = sep + 1;
			}

			if (strlen(imfs_path) > 0 && strlen(actual_path) > 0) {
				fprintf(stderr, "dumping %s -> %s\n", imfs_path,
					actual_path);
				dump_file(imfs_path, actual_path);
			}
		}

		entry = strtok(NULL, ";");
	}

	free(list);
}

/* Logging helper: prints the syscall name, its args and the return value. */
static inline void sys_log_args(const char *name, unsigned long a0,
				unsigned long a1, unsigned long a2,
				unsigned long a3, unsigned long a4,
				unsigned long a5, long ret) {
	char buf[512];
	size_t pos = 0;
	unsigned long args[6] = { a0, a1, a2, a3, a4, a5 };
	int first = 1;

	pos += snprintf(buf + pos, sizeof(buf) - pos, "%s (", name);
	for (int i = 0; i < 6; i++) {
		if (args[i] == 0xdeadbeefdeadbeefULL)
			continue;
		if (!first)
			pos += snprintf(buf + pos, sizeof(buf) - pos, ", ");
		pos += snprintf(buf + pos, sizeof(buf) - pos, "%lu", args[i]);
		first = 0;
	}
	snprintf(buf + pos, sizeof(buf) - pos, ") = %ld\n", ret);
	fprintf(stderr, "%s", buf);
}

#ifdef DIAG
#define SYS_LOG(name, ret)                                                     \
	sys_log_args((name), a[0], a[1], a[2], a[3], a[4], a[5], (long)(ret))
#else
#define SYS_LOG(...) ((void)0)
#endif

/*
 * FS syscall handlers. IMFS registers open, lseek, read, write, close, fcntl,
 * unlink, pread and pwrite.
 */

long open_grate(pid_t cage, const int ac[6], unsigned long a[6]) {
	int thiscage = getpid();
	int cageid = cage_index(cage);

	/* Pull the path string out of the cage that owns the pointer (ac[0]). */
	char *pathname = malloc(256);
	if (!pathname) {
		perror("malloc failed");
		exit(EXIT_FAILURE);
	}

	copy_data_between_cages(arg_owner(ac, 0, cage), a[0], thiscage,
				(unsigned long)pathname, 256, THREEI_COPY_STRNCPY);

	long ifd = imfs_open(cageid, pathname, (int)a[1], (mode_t)a[2]);
	SYS_LOG("OPEN", ifd);

	free(pathname);
	return ifd;
}

/*
 * glibc routes open()->openat(AT_FDCWD,...) and unlink()->unlinkat(AT_FDCWD,.,0)
 * on x86-64, so a cage built against glibc never issues the legacy open(2) /
 * unlink(87) numbers. Intercept the *at forms too. openat args:
 *   a[0]=dirfd, a[1]=path(ptr, owned by ac[1]), a[2]=flags, a[3]=mode.
 */
long openat_grate(pid_t cage, const int ac[6], unsigned long a[6]) {
	int thiscage = getpid();
	int cageid = cage_index(cage);

	char *pathname = malloc(256);
	if (!pathname) {
		perror("malloc failed");
		exit(EXIT_FAILURE);
	}

	copy_data_between_cages(arg_owner(ac, 1, cage), a[1], thiscage,
				(unsigned long)pathname, 256, THREEI_COPY_STRNCPY);

	long ifd = imfs_openat(cageid, (int)a[0], pathname, (int)a[2],
			       (mode_t)a[3]);
	SYS_LOG("OPENAT", ifd);

	free(pathname);
	return ifd;
}

/* unlinkat args: a[0]=dirfd, a[1]=path(ptr, owned by ac[1]), a[2]=flags. */
long unlinkat_grate(pid_t cage, const int ac[6], unsigned long a[6]) {
	int thiscage = getpid();

	char *pathname = malloc(256);
	if (!pathname) {
		perror("malloc failed");
		exit(EXIT_FAILURE);
	}

	copy_data_between_cages(arg_owner(ac, 1, cage), a[1], thiscage,
				(unsigned long)pathname, 256, THREEI_COPY_STRNCPY);

	long ret = imfs_unlink(cage_index(cage), pathname);
	SYS_LOG("UNLINKAT", ret);

	free(pathname);
	return ret;
}

long fcntl_grate(pid_t cage, const int ac[6], unsigned long a[6]) {
	(void)ac;
	long ret = imfs_fcntl(cage_index(cage), (int)a[0], (int)a[1], (int)a[2]);
	SYS_LOG("FCNTL", ret);
	return ret;
}

long unlink_grate(pid_t cage, const int ac[6], unsigned long a[6]) {
	int thiscage = getpid();

	char *pathname = malloc(256);
	if (!pathname) {
		perror("malloc failed");
		exit(EXIT_FAILURE);
	}

	copy_data_between_cages(arg_owner(ac, 0, cage), a[0], thiscage,
				(unsigned long)pathname, 256, THREEI_COPY_STRNCPY);

	long ret = imfs_unlink(cage_index(cage), pathname);
	SYS_LOG("UNLINK", ret);

	free(pathname);
	return ret;
}

long close_grate(pid_t cage, const int ac[6], unsigned long a[6]) {
	(void)ac;
	long ret = imfs_close(cage_index(cage), (int)a[0]);
	SYS_LOG("CLOSE", ret);
	return ret;
}

long lseek_grate(pid_t cage, const int ac[6], unsigned long a[6]) {
	(void)ac;
	long ret = imfs_lseek(cage_index(cage), (int)a[0], (off_t)a[1], (int)a[2]);
	SYS_LOG("LSEEK", ret);
	return ret;
}

/*
 * read / pread: service out of the IMFS into a grate buffer, then stage the
 * result back into the cage's OUT buffer (args[1], owned by arg_cage[1]).
 */
long read_grate(pid_t cage, const int ac[6], unsigned long a[6]) {
	int thiscage = getpid();
	int cageid = cage_index(cage);
	int fd = (int)a[0];
	size_t count = (size_t)a[2];

	char *buf = malloc(count ? count : 1);
	if (!buf) {
		fprintf(stderr, "malloc failed\n");
		exit(1);
	}

	ssize_t ret = imfs_read(cageid, fd, buf, count);

	/* read() is sometimes called with a NULL buffer; skip the copy then. */
	if (a[1] != 0 && ret > 0)
		copy_data_between_cages(thiscage, (unsigned long)buf,
					arg_owner(ac, 1, cage), a[1],
					(size_t)ret, THREEI_COPY_MEMCPY);

	SYS_LOG("READ", ret);
	free(buf);
	return ret;
}

long pread_grate(pid_t cage, const int ac[6], unsigned long a[6]) {
	int thiscage = getpid();
	int cageid = cage_index(cage);
	int fd = (int)a[0];
	size_t count = (size_t)a[2];
	off_t offset = (off_t)a[3];

	char *buf = malloc(count ? count : 1);
	if (!buf) {
		fprintf(stderr, "malloc failed\n");
		exit(1);
	}

	ssize_t ret = imfs_pread(cageid, fd, buf, count, offset);

	if (a[1] != 0 && ret > 0)
		copy_data_between_cages(thiscage, (unsigned long)buf,
					arg_owner(ac, 1, cage), a[1],
					(size_t)ret, THREEI_COPY_MEMCPY);

	SYS_LOG("PREAD", ret);
	free(buf);
	return ret;
}

long write_grate(pid_t cage, const int ac[6], unsigned long a[6]) {
	int thiscage = getpid();
	int cageid = cage_index(cage);
	int fd = (int)a[0];
	size_t count = (size_t)a[2];

	char *buffer = malloc(count ? count : 1);
	if (!buffer) {
		perror("malloc failed");
		exit(1);
	}

	copy_data_between_cages(arg_owner(ac, 1, cage), a[1], thiscage,
				(unsigned long)buffer, count, THREEI_COPY_MEMCPY);

	long ret;
	if (fd < 3)
		ret = write(fd, buffer, count);
	else
		ret = imfs_write(cageid, fd, buffer, count);

	SYS_LOG("WRITE", ret);
	free(buffer);
	return ret;
}

long pwrite_grate(pid_t cage, const int ac[6], unsigned long a[6]) {
	int thiscage = getpid();
	int cageid = cage_index(cage);
	int fd = (int)a[0];
	size_t count = (size_t)a[2];
	off_t offset = (off_t)a[3];

	char *buffer = malloc(count ? count : 1);
	if (!buffer) {
		perror("malloc failed");
		exit(1);
	}

	copy_data_between_cages(arg_owner(ac, 1, cage), a[1], thiscage,
				(unsigned long)buffer, count, THREEI_COPY_MEMCPY);

	long ret;
	if (fd < 3)
		ret = write(fd, buffer, count);
	else
		ret = imfs_pwrite(cageid, fd, buffer, count, offset);

	SYS_LOG("PWRITE", ret);
	free(buffer);
	return ret;
}

/* (cage-syscall-nr, handler) table, registered for the cage below. */
static const struct {
	__u32 nr;
	threei_handler_fn fn;
} HANDLERS[] = {
	{ __NR_read,	 read_grate     },
	{ __NR_write,	 write_grate    },
	{ __NR_open,	 open_grate     },
	{ __NR_openat,	 openat_grate   },
	{ __NR_close,	 close_grate    },
	{ __NR_lseek,	 lseek_grate    },
	{ __NR_pread64,	 pread_grate    },
	{ __NR_pwrite64, pwrite_grate   },
	{ __NR_fcntl,	 fcntl_grate    },
	{ __NR_unlink,	 unlink_grate   },
	{ __NR_unlinkat, unlinkat_grate },
};

int main(int argc, char *argv[]) {
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <cage_file> [args...]\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	int grateid = getpid();

	/* Bring up the IMFS and preload host files BEFORE the cage can run, so
	 * the filesystem is populated by the time any syscall is serviced. */
	imfs_init();
	preload_files = getenv("PRELOADS");
	preloads(preload_files);

	pid_t cageid = fork();
	if (cageid < 0) {
		perror("fork failed");
		exit(EXIT_FAILURE);
	}

	if (cageid == 0) {
		/*
		 * Register every handler for this (soon-to-be) cage, pointing at
		 * the grate's handler functions, then exec the cage image.
		 * Registering here, before execv, means the handlers are in
		 * place the instant the cage starts issuing syscalls -- no setup
		 * semaphore needed. The grate's transparent runtime (threei.h
		 * constructor) services them from the parent.
		 */
		for (size_t i = 0; i < sizeof(HANDLERS) / sizeof(HANDLERS[0]);
		     i++) {
			if (register_handler(getpid(), HANDLERS[i].nr, grateid,
					     (unsigned long)HANDLERS[i].fn) < 0) {
				perror("register_handler failed");
				_exit(EXIT_FAILURE);
			}
		}

		execv(argv[1], &argv[1]);
		perror("execv failed");
		_exit(EXIT_FAILURE);
	}

	/* Grate: wait for the cage to finish; its syscalls are serviced
	 * asynchronously by the 3i runtime threads. */
	int status, w;
	while ((w = wait(&status)) < 0 && errno == EINTR)
		;

	/* Dump selected IMFS files back to disk after the cage exits. */
	dump_files = getenv("DUMPS");
	dump_outputs(dump_files);

	return WIFEXITED(status) ? WEXITSTATUS(status) : EXIT_FAILURE;
}
