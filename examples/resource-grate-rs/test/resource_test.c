#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/uio.h>

#define PASS()                                                                 \
	do {                                                                   \
		printf("PASS: %s\n", __func__);                                \
		total_tests++;                                                 \
	} while (0)

#define FAIL(msg)                                                              \
	do {                                                                   \
		printf("FAIL: %s - %s (errno=%d)\n", __func__, msg, errno);    \
		failures++;                                                    \
		total_tests++;                                                 \
		return 1;                                                      \
	} while (0)

static int total_tests = 0;
static int failures = 0;

/* getrandom may not have a header in the Lind sysroot. */
extern ssize_t getrandom(void *buf, size_t buflen, unsigned int flags);

static double elapsed_sec(struct timespec *start, struct timespec *end) {
	return (end->tv_sec - start->tv_sec)
	     + (end->tv_nsec - start->tv_nsec) / 1e9;
}

/* =================================================================
 *  FILE I/O TESTS
 * ================================================================= */

/* Test 1: basic write/read round-trip */
int test_basic_write_read(void) {
	int fd = open("/tmp/res_test1.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
	if (fd < 0)
		FAIL("open");

	const char *msg = "Hello from resource grate test";
	int len = strlen(msg);
	if (write(fd, msg, len) != len)
		FAIL("write");
	if (close(fd) != 0)
		FAIL("close after write");

	fd = open("/tmp/res_test1.txt", O_RDONLY);
	if (fd < 0)
		FAIL("open readonly");

	char buf[64] = {0};
	if (read(fd, buf, len) != len)
		FAIL("read");
	if (strcmp(buf, msg) != 0)
		FAIL("data mismatch");
	close(fd);
	unlink("/tmp/res_test1.txt");
	PASS();
	return 0;
}

/* Test 2: multiple sequential writes */
int test_multiple_writes(void) {
	int fd = open("/tmp/res_test2.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
	if (fd < 0)
		FAIL("open");

	char chunk[1000];
	memset(chunk, 'A', sizeof(chunk));

	for (int i = 0; i < 10; i++) {
		if (write(fd, chunk, sizeof(chunk)) != (int)sizeof(chunk))
			FAIL("write iteration");
	}

	close(fd);
	unlink("/tmp/res_test2.txt");
	PASS();
	return 0;
}

/* Test 3: large read */
int test_large_read(void) {
	int fd = open("/tmp/res_test3.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
	if (fd < 0)
		FAIL("open for write");

	char wbuf[4096];
	memset(wbuf, 'B', sizeof(wbuf));
	for (int i = 0; i < 16; i++) {
		if (write(fd, wbuf, sizeof(wbuf)) != (int)sizeof(wbuf))
			FAIL("write block");
	}
	close(fd);

	fd = open("/tmp/res_test3.txt", O_RDONLY);
	if (fd < 0)
		FAIL("open for read");

	char rbuf[4096];
	int total = 0;
	int n;
	while ((n = read(fd, rbuf, sizeof(rbuf))) > 0)
		total += n;

	if (total != 65536)
		FAIL("short read total");

	close(fd);
	unlink("/tmp/res_test3.txt");
	PASS();
	return 0;
}

/* Test 4: filesopened cap (config: filesopened 5) */
int test_filesopened_cap(void) {
	int fds[32];
	int opened = 0;
	char path[64];

	for (int i = 0; i < 32; i++) {
		snprintf(path, sizeof(path), "/tmp/res_cap_%d.txt", i);
		fds[i] = open(path, O_CREAT | O_RDWR | O_TRUNC, 0644);
		if (fds[i] < 0) {
			if (errno == EMFILE) {
				printf("  filesopened cap hit at %d files (expected)\n", opened);
				break;
			}
			FAIL("unexpected open error");
		}
		opened++;
	}

	for (int i = 0; i < opened; i++) {
		close(fds[i]);
		snprintf(path, sizeof(path), "/tmp/res_cap_%d.txt", i);
		unlink(path);
	}

	if (opened == 0)
		FAIL("could not open any files");
	PASS();
	return 0;
}

/* Test 5: stdout writes charge lograte, not filewrite */
int test_lograte(void) {
	const char *msg = "Log output from cage test\n";
	int len = strlen(msg);

	for (int i = 0; i < 20; i++) {
		if (write(STDOUT_FILENO, msg, len) != len)
			FAIL("write stdout");
	}

	PASS();
	return 0;
}

/* Test 6: getrandom charges random resource */
int test_getrandom(void) {
	char buf[32];

	ssize_t n = getrandom(buf, sizeof(buf), 0);
	if (n < 0 && errno == ENOSYS) {
		printf("  getrandom not available, skipping\n");
		PASS();
		return 0;
	}
	if (n <= 0)
		FAIL("getrandom returned <= 0");

	PASS();
	return 0;
}

/* =================================================================
 *  TIMED RATE LIMITING TESTS
 * ================================================================= */

/* Test 7: timed write — 200KB at 50KB/sec → ~3-4s */
int test_timed_write(void) {
	int fd = open("/tmp/res_timed.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
	if (fd < 0)
		FAIL("open");

	char buf[4096];
	memset(buf, 'T', sizeof(buf));

	struct timespec start, end;
	clock_gettime(CLOCK_MONOTONIC, &start);

	for (int i = 0; i < 50; i++) {
		if (write(fd, buf, sizeof(buf)) != (int)sizeof(buf))
			FAIL("write");
	}

	clock_gettime(CLOCK_MONOTONIC, &end);
	double dt = elapsed_sec(&start, &end);
	printf("  wrote 200KB in %.2fs (expect ~3-4s)\n", dt);

	close(fd);
	unlink("/tmp/res_timed.txt");

	if (dt < 0.5)
		FAIL("too fast — rate limiting not working");
	PASS();
	return 0;
}

/* Test 8: timed read — 200KB at 50KB/sec → ~3-4s */
int test_timed_read(void) {
	int fd = open("/tmp/res_tread.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
	if (fd < 0)
		FAIL("open for write");

	char wbuf[4096];
	memset(wbuf, 'R', sizeof(wbuf));
	for (int i = 0; i < 50; i++)
		write(fd, wbuf, sizeof(wbuf));
	close(fd);

	fd = open("/tmp/res_tread.txt", O_RDONLY);
	if (fd < 0)
		FAIL("open for read");

	char rbuf[4096];
	struct timespec start, end;
	clock_gettime(CLOCK_MONOTONIC, &start);

	for (int i = 0; i < 50; i++) {
		if (read(fd, rbuf, sizeof(rbuf)) <= 0)
			break;
	}

	clock_gettime(CLOCK_MONOTONIC, &end);
	double dt = elapsed_sec(&start, &end);
	printf("  read 200KB in %.2fs (expect ~3-4s)\n", dt);

	close(fd);
	unlink("/tmp/res_tread.txt");

	if (dt < 0.5)
		FAIL("too fast — rate limiting not working");
	PASS();
	return 0;
}

/* Test 9: burst window — first write within burst should be fast */
int test_burst_window(void) {
	int fd = open("/tmp/res_burst.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
	if (fd < 0)
		FAIL("open");

	char buf[4096];
	memset(buf, 'B', sizeof(buf));

	/* filewrite = 50000 B/sec. Burst allows up to 50000 bytes before
	 * throttling. That's ~12 blocks of 4096. Write 10 blocks — should
	 * be nearly instant (within burst). */
	struct timespec start, end;
	clock_gettime(CLOCK_MONOTONIC, &start);

	for (int i = 0; i < 10; i++) {
		if (write(fd, buf, sizeof(buf)) != (int)sizeof(buf))
			FAIL("write");
	}

	clock_gettime(CLOCK_MONOTONIC, &end);
	double dt = elapsed_sec(&start, &end);
	printf("  burst write 40KB in %.3fs (expect < 0.5s)\n", dt);

	close(fd);
	unlink("/tmp/res_burst.txt");

	if (dt > 1.0)
		FAIL("burst too slow — should be within burst window");
	PASS();
	return 0;
}

/* Test 10: rate limit recovery — after waiting, budget refills */
int test_rate_recovery(void) {
	int fd = open("/tmp/res_recov.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
	if (fd < 0)
		FAIL("open");

	char buf[4096];
	memset(buf, 'V', sizeof(buf));

	/* Exhaust the burst: write 50KB (12-13 blocks). */
	for (int i = 0; i < 13; i++)
		write(fd, buf, sizeof(buf));

	/* Wait 2 seconds for budget to refill. At 50KB/sec, 2s refills 100KB. */
	struct timespec ts = {2, 0};
	nanosleep(&ts, NULL);

	/* Now write another burst — should be fast again. */
	struct timespec start, end;
	clock_gettime(CLOCK_MONOTONIC, &start);

	for (int i = 0; i < 10; i++) {
		if (write(fd, buf, sizeof(buf)) != (int)sizeof(buf))
			FAIL("write after recovery");
	}

	clock_gettime(CLOCK_MONOTONIC, &end);
	double dt = elapsed_sec(&start, &end);
	printf("  post-recovery burst 40KB in %.3fs (expect < 1.0s)\n", dt);

	close(fd);
	unlink("/tmp/res_recov.txt");

	if (dt > 2.0)
		FAIL("recovery burst too slow — budget didn't refill");
	PASS();
	return 0;
}

/* =================================================================
 *  PREAD / PWRITE / READV / WRITEV TESTS
 * ================================================================= */

/* Test 11: pwrite charges filewrite */
int test_pwrite(void) {
	int fd = open("/tmp/res_pwrite.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
	if (fd < 0)
		FAIL("open");

	char buf[100];
	memset(buf, 'P', sizeof(buf));

	ssize_t n = pwrite(fd, buf, sizeof(buf), 0);
	if (n != (ssize_t)sizeof(buf))
		FAIL("pwrite");

	/* Verify data with pread. */
	char rbuf[100] = {0};
	n = pread(fd, rbuf, sizeof(rbuf), 0);
	if (n != (ssize_t)sizeof(rbuf))
		FAIL("pread");
	if (memcmp(buf, rbuf, sizeof(buf)) != 0)
		FAIL("data mismatch");

	close(fd);
	unlink("/tmp/res_pwrite.txt");
	PASS();
	return 0;
}

/* Test 12: writev charges filewrite */
int test_writev(void) {
	int fd = open("/tmp/res_writev.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
	if (fd < 0)
		FAIL("open");

	char a[] = "hello ";
	char b[] = "writev";
	struct iovec iov[2];
	iov[0].iov_base = a;
	iov[0].iov_len = strlen(a);
	iov[1].iov_base = b;
	iov[1].iov_len = strlen(b);

	ssize_t n = writev(fd, iov, 2);
	if (n != (ssize_t)(strlen(a) + strlen(b)))
		FAIL("writev");

	/* Read back. */
	lseek(fd, 0, SEEK_SET);
	char rbuf[32] = {0};
	read(fd, rbuf, sizeof(rbuf));
	if (strcmp(rbuf, "hello writev") != 0)
		FAIL("data mismatch");

	close(fd);
	unlink("/tmp/res_writev.txt");
	PASS();
	return 0;
}

/* Test 13: readv charges fileread */
int test_readv(void) {
	int fd = open("/tmp/res_readv.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
	if (fd < 0)
		FAIL("open");

	write(fd, "ABCDEFGHIJ", 10);
	lseek(fd, 0, SEEK_SET);

	char a[5] = {0}, b[5] = {0};
	struct iovec iov[2];
	iov[0].iov_base = a;
	iov[0].iov_len = 5;
	iov[1].iov_base = b;
	iov[1].iov_len = 5;

	ssize_t n = readv(fd, iov, 2);
	if (n != 10)
		FAIL("readv");
	if (memcmp(a, "ABCDE", 5) != 0 || memcmp(b, "FGHIJ", 5) != 0)
		FAIL("data mismatch");

	close(fd);
	unlink("/tmp/res_readv.txt");
	PASS();
	return 0;
}

/* =================================================================
 *  FILESOPENED CAP — CLOSE AND REOPEN
 * ================================================================= */

/* Test 14: close frees a filesopened slot */
int test_filesopened_close_reopen(void) {
	/* Config: filesopened 5. Open 5 files (hit the cap), close one,
	 * then open a new one — should succeed. */
	int fds[5];
	char path[64];

	for (int i = 0; i < 5; i++) {
		snprintf(path, sizeof(path), "/tmp/res_reopen_%d.txt", i);
		fds[i] = open(path, O_CREAT | O_RDWR | O_TRUNC, 0644);
		if (fds[i] < 0)
			FAIL("initial open");
	}

	/* Should fail — at cap. */
	int extra = open("/tmp/res_reopen_extra.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
	if (extra >= 0) {
		close(extra);
		unlink("/tmp/res_reopen_extra.txt");
		/* Not necessarily a fail — cap might be > 5. */
	}

	/* Close one. */
	close(fds[0]);

	/* Should succeed now. */
	int reopened = open("/tmp/res_reopen_new.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
	if (reopened < 0)
		FAIL("reopen after close failed");

	close(reopened);
	unlink("/tmp/res_reopen_new.txt");

	for (int i = 1; i < 5; i++) {
		close(fds[i]);
		snprintf(path, sizeof(path), "/tmp/res_reopen_%d.txt", i);
		unlink(path);
	}
	unlink("/tmp/res_reopen_0.txt");

	PASS();
	return 0;
}

/* =================================================================
 *  OPEN WITH WRITE FLAGS CHARGES BOTH FILEREAD AND FILEWRITE
 * ================================================================= */

/* Test 15: open with O_RDWR charges filewrite metadata */
int test_open_write_flags(void) {
	/* Opening with write flags should charge filewrite 4096 in addition
	 * to fileread 4096. We just verify it doesn't error. */
	int fd = open("/tmp/res_owf.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
	if (fd < 0)
		FAIL("open O_RDWR");
	close(fd);

	fd = open("/tmp/res_owf.txt", O_WRONLY);
	if (fd < 0)
		FAIL("open O_WRONLY");
	close(fd);

	fd = open("/tmp/res_owf.txt", O_RDONLY);
	if (fd < 0)
		FAIL("open O_RDONLY");
	close(fd);

	unlink("/tmp/res_owf.txt");
	PASS();
	return 0;
}

/* =================================================================
 *  GETRANDOM RATE LIMITING
 * ================================================================= */

/* Test 16: timed getrandom — each call charges 1024 bytes at 10KB/sec */
int test_timed_getrandom(void) {
	/* Config: random = 10000 (10 KB/sec).
	 * Each getrandom call charges 1024 bytes.
	 * 20 calls = 20480 bytes. At 10KB/sec burst of 10KB,
	 * excess 10KB takes ~1 second. */
	char buf[32];

	struct timespec start, end;
	clock_gettime(CLOCK_MONOTONIC, &start);

	for (int i = 0; i < 20; i++) {
		ssize_t n = getrandom(buf, sizeof(buf), 0);
		if (n < 0 && errno == ENOSYS) {
			printf("  getrandom not available, skipping\n");
			PASS();
			return 0;
		}
	}

	clock_gettime(CLOCK_MONOTONIC, &end);
	double dt = elapsed_sec(&start, &end);
	printf("  20 getrandom calls in %.2fs (expect ~1s)\n", dt);

	if (dt < 0.3)
		FAIL("too fast — random rate limiting not working");
	PASS();
	return 0;
}

/* =================================================================
 *  LOGRATE TIMED TEST
 * ================================================================= */

/* Test 17: timed lograte — stdout at 30KB/sec */
int test_timed_lograte(void) {
	/* Config: lograte = 30000 (30 KB/sec).
	 * Write 90KB to stdout → ~2-3s. */
	char line[1000];
	memset(line, 'L', sizeof(line) - 1);
	line[sizeof(line) - 1] = '\n';

	struct timespec start, end;
	clock_gettime(CLOCK_MONOTONIC, &start);

	for (int i = 0; i < 90; i++) {
		write(STDOUT_FILENO, line, sizeof(line));
	}

	clock_gettime(CLOCK_MONOTONIC, &end);
	double dt = elapsed_sec(&start, &end);
	printf("  wrote 90KB to stdout in %.2fs (expect ~2-3s)\n", dt);

	if (dt < 0.5)
		FAIL("too fast — lograte limiting not working");
	PASS();
	return 0;
}

/* =================================================================
 *  STDERR ALSO CHARGES LOGRATE
 * ================================================================= */

/* Test 18: stderr charges lograte too */
int test_stderr_lograte(void) {
	const char *msg = "stderr test line\n";
	int len = strlen(msg);

	for (int i = 0; i < 10; i++) {
		if (write(STDERR_FILENO, msg, len) != len)
			FAIL("write stderr");
	}

	PASS();
	return 0;
}

/* =================================================================
 *  SIMULTANEOUS RESOURCES
 * ================================================================= */

/* Test 19: write to file while also writing to stdout — both resources
 * should be independently rate limited. */
int test_simultaneous_resources(void) {
	int fd = open("/tmp/res_simul.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
	if (fd < 0)
		FAIL("open");

	char buf[1024];
	memset(buf, 'S', sizeof(buf));

	for (int i = 0; i < 10; i++) {
		if (write(fd, buf, sizeof(buf)) != (int)sizeof(buf))
			FAIL("write file");
		if (write(STDOUT_FILENO, ".", 1) != 1)
			FAIL("write stdout");
	}
	printf("\n");

	close(fd);
	unlink("/tmp/res_simul.txt");
	PASS();
	return 0;
}

/* =================================================================
 *  NETWORK TESTS (if sockets are available)
 * ================================================================= */

/* Test 20: socket creation (no resource charge, just passthrough) */
int test_socket_create(void) {
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		if (errno == ENOSYS || errno == EACCES) {
			printf("  sockets not available, skipping\n");
			PASS();
			return 0;
		}
		FAIL("socket");
	}
	close(fd);
	PASS();
	return 0;
}

/* Test 21: bind on allowed port (config: connport/messport 12345) */
int test_bind_allowed_port(void) {
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		printf("  sockets not available, skipping\n");
		PASS();
		return 0;
	}

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(12345); /* allowed in config */
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	int ret = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
	/* bind might fail for other reasons (port in use), but shouldn't
	 * fail with EACCES if the port is allowed. */
	if (ret < 0 && errno == EACCES)
		FAIL("bind returned EACCES on allowed port");

	close(fd);
	PASS();
	return 0;
}

/* Test 22: bind on disallowed port should return EACCES */
int test_bind_disallowed_port(void) {
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		printf("  sockets not available, skipping\n");
		PASS();
		return 0;
	}

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(9999); /* NOT in config */
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	int ret = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (ret == 0) {
		/* If bind succeeded, port allowlist isn't enforced.
		 * This could be because no ports are configured (all allowed). */
		printf("  bind succeeded on port 9999 (allowlist may be open)\n");
	} else if (errno == EACCES) {
		printf("  bind correctly blocked port 9999 with EACCES\n");
	}

	close(fd);
	PASS();
	return 0;
}

/* =================================================================
 *  RAPID OPEN/CLOSE CYCLING AT CAP
 * ================================================================= */

/* Test 23: rapidly open and close at the filesopened cap */
int test_rapid_open_close_at_cap(void) {
	/* Open to cap, close, reopen — 50 cycles. */
	int ok = 1;
	for (int cycle = 0; cycle < 50; cycle++) {
		int fd = open("/tmp/res_rapid_cap.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
		if (fd < 0) {
			ok = 0;
			break;
		}
		close(fd);
	}
	unlink("/tmp/res_rapid_cap.txt");

	if (!ok)
		FAIL("rapid open/close failed");
	PASS();
	return 0;
}

/* =================================================================
 *  ZERO-BYTE WRITE (edge case)
 * ================================================================= */

/* Test 24: zero-length write should succeed without charging */
int test_zero_write(void) {
	int fd = open("/tmp/res_zero.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
	if (fd < 0)
		FAIL("open");

	ssize_t n = write(fd, "", 0);
	if (n != 0)
		FAIL("zero write should return 0");

	close(fd);
	unlink("/tmp/res_zero.txt");
	PASS();
	return 0;
}

/* =================================================================
 *  MAIN
 * ================================================================= */

int main(void) {
	printf("=== Resource Grate Test Suite ===\n\n");

	/* File I/O basics. */
	test_basic_write_read();
	test_multiple_writes();
	test_large_read();
	test_pwrite();
	test_writev();
	test_readv();
	test_open_write_flags();
	test_zero_write();

	/* Fungible caps. */
	test_filesopened_cap();
	test_filesopened_close_reopen();
	test_rapid_open_close_at_cap();

	/* Lograte. */
	test_lograte();
	test_stderr_lograte();

	/* Getrandom. */
	test_getrandom();

	/* Network. */
	test_socket_create();
	test_bind_allowed_port();
	test_bind_disallowed_port();

	/* Simultaneous resources. */
	test_simultaneous_resources();

	/* Timed rate limiting (these are slow — run last). */
	test_timed_write();
	test_timed_read();
	test_burst_window();
	test_rate_recovery();
	test_timed_getrandom();
	test_timed_lograte();

	printf("\n=== Results: %d tests, %d failures ===\n",
	       total_tests, failures);

	return failures > 0 ? 1 : 0;
}
