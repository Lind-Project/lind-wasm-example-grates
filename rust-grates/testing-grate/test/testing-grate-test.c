/// This test assumes that it is run like so:
///
/// lind-boot testing-grate.cwasm -s 0:100,1:, testing-grate-test.cwasm

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

int tests_run, tests_passed;

#define CHECK(desc, cond)                                                      \
	do {                                                                   \
		tests_run++;                                                   \
		if (cond) {                                                    \
			printf("  PASS: %s\n", desc);                          \
			tests_passed++;                                        \
		} else {                                                       \
			printf("  FAIL: %s (errno=%d)\n", desc, errno);        \
		}                                                              \
	} while (0)

int main() {
	printf("\n[testing-grate tests]\n");
	tests_run = 0;
	tests_passed = 0;

	char buf[10];
	int ret;
	char *msg = "hello world this is a testing message aimed at the void.";

	// Ensure reads are stubbed.
	ret = read(10, buf, 10);
	CHECK("read(10,...,10)", ret == 100);
	ret = read(0, buf, 4096);
	CHECK("read(0,...,4096)", ret == 100);

	// Ensure writes are fine.
	int fd = open("/dev/null", O_WRONLY, 0);
	ret = write(fd, msg, 5);
	CHECK("write(/dev/null, ...,5", ret == 5);

	ret = write(fd, msg, 10);
	CHECK("write(/dev/null, ...,10", ret == 10);

	ret = write(fd, msg, 128);
	CHECK("write(/dev/null, ...,128", ret == 128);

	printf("\n=== results: %d/%d passed ===\n", tests_passed, tests_run);
	return (tests_passed == tests_run) ? 0 : 1;
}
