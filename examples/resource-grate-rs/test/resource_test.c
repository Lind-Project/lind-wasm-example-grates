#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PASS()                                                                 \
	do {                                                                   \
		printf("PASS: %s\n", __func__);                                \
		total_tests++;                                                 \
	} while (0)

#define FAIL(msg)                                                              \
	do {                                                                   \
		printf("FAIL: %s - %s (errno=%d)\n", __func__, msg, errno);    \
		failures++;                                                    \
		return 1;                                                      \
	} while (0)

static int total_tests = 0;
static int failures = 0;

/* -----------------------------------------------------------------
 *  Test 1: basic write/read round-trip through the grate
 * ----------------------------------------------------------------- */
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
	if (close(fd) != 0)
		FAIL("close after read");

	unlink("/tmp/res_test1.txt");
	PASS();
	return 0;
}

/* -----------------------------------------------------------------
 *  Test 2: multiple sequential writes accumulate filewrite charges
 * ----------------------------------------------------------------- */
int test_multiple_writes(void) {
	int fd = open("/tmp/res_test2.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
	if (fd < 0)
		FAIL("open");

	/* Write 10 x 1000 bytes = 10 000 bytes.
	 * With block rounding (ceil to 4096), each write costs 4096,
	 * so total filewrite charge = 40 960. */
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

/* -----------------------------------------------------------------
 *  Test 3: large read to exercise fileread rate limiting
 * ----------------------------------------------------------------- */
int test_large_read(void) {
	/* Create a 64 KB file first. */
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

	/* Read the whole file back in 4 KB chunks. */
	fd = open("/tmp/res_test3.txt", O_RDONLY);
	if (fd < 0)
		FAIL("open for read");

	char rbuf[4096];
	int total = 0;
	int n;
	while ((n = read(fd, rbuf, sizeof(rbuf))) > 0) {
		total += n;
	}
	if (total != 65536)
		FAIL("short read total");

	close(fd);
	unlink("/tmp/res_test3.txt");
	PASS();
	return 0;
}

/* -----------------------------------------------------------------
 *  Test 4: filesopened cap — open many files, expect EMFILE eventually
 *
 *  This test only triggers if the resource config sets a low
 *  "filesopened" limit (e.g. 5).  If unlimited the test just passes.
 * ----------------------------------------------------------------- */
int test_filesopened_cap(void) {
	int fds[32];
	int opened = 0;
	char path[64];

	for (int i = 0; i < 32; i++) {
		snprintf(path, sizeof(path), "/tmp/res_cap_%d.txt", i);
		fds[i] = open(path, O_CREAT | O_RDWR | O_TRUNC, 0644);
		if (fds[i] < 0) {
			/* Expected: EMFILE when cap is reached. */
			if (errno == EMFILE) {
				printf("  filesopened cap hit at %d files "
				       "(this is expected)\n",
				       opened);
				break;
			}
			FAIL("unexpected open error");
		}
		opened++;
	}

	/* Clean up. */
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

/* -----------------------------------------------------------------
 *  Test 5: stdout/stderr writes (lograte resource)
 * ----------------------------------------------------------------- */
int test_lograte(void) {
	/* These writes should charge lograte, not filewrite. */
	const char *msg = "Log output from cage test\n";
	int len = strlen(msg);

	for (int i = 0; i < 20; i++) {
		if (write(STDOUT_FILENO, msg, len) != len)
			FAIL("write stdout");
	}

	PASS();
	return 0;
}

/* -----------------------------------------------------------------
 *  Test 6: getrandom (random resource)
 * ----------------------------------------------------------------- */
/* getrandom may not have a header in the Lind sysroot. */
extern ssize_t getrandom(void *buf, size_t buflen, unsigned int flags);

int test_getrandom(void) {
	char buf[32];

	/* If getrandom is available, each call charges 1024 bytes. */
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

/* ================================================================= */

int main(void) {
	printf("=== Resource Grate Test Suite ===\n\n");

	test_basic_write_read();
	test_multiple_writes();
	test_large_read();
	test_filesopened_cap();
	test_lograte();
	test_getrandom();

	printf("\n=== Results: %d tests, %d failures ===\n",
	       total_tests, failures);

	return failures > 0 ? 1 : 0;
}
