/* fs_routing_test.c - routing-only tests for the namespace clamping grate.
 *
 * These tests assume clamped FS syscalls are stubbed to fixed negative errno
 * values.
 * We only verify that:
 *   - syscalls on /tmp/ are routed to the clamp, and
 *   - syscalls on non-/tmp paths are not.
 *
 * Example invocation:
 *      lind-boot fs-routing-clamp.cwasm --prefix /tmp %{ testing-grate.cwasm
 * -s 2:-167,4:-167,21:-167,83:-167,84:-167,87:-167
 * fs-routing-clamp.cwasm --prefix /tmp/inner %{ testing-grate.cwasm -s 2:-166 %}
 * %} fs_routing_test.cwasm
 *
 * We use testing-grate to stub outer clamped syscalls to -167 and inner
 * clamped open(2) calls to -166. Libc converts these to ret=-1 and errno.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>

static int tests_run = 0;
static int tests_passed = 0;

#define OUTER_CLAMP_ERRNO 167
#define INNER_CLAMP_ERRNO 166

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

#define EXPECT_ERRNO(desc, expr, expected_errno)                              \
	do {                                                                  \
		errno = 0;                                                    \
		CHECK(desc, ((expr) == -1 && errno == (expected_errno)));     \
	} while (0)

static void test_open_routing(void) {
	printf("\n[test_open_routing]\n");

	EXPECT_ERRNO("open /tmp/ns_test_file routed to outer clamp",
		     open("/tmp/ns_test_file", O_CREAT | O_RDWR, 0644),
		     OUTER_CLAMP_ERRNO);

	EXPECT_ERRNO("open /tmp/inner routed to inner clamp",
		     open("/tmp/inner", O_CREAT | O_RDWR, 0644),
		     INNER_CLAMP_ERRNO);

	int fd = open("/dev/null", O_RDWR);
	CHECK("open /dev/null not clamped", fd >= 0);
	if (fd >= 0)
		close(fd);
}

static void test_path_syscalls(void) {
	printf("\n[test_path_syscalls]\n");

	struct stat st;

	EXPECT_ERRNO("mkdir /tmp/ns_test_dir routed to outer clamp",
		     mkdir("/tmp/ns_test_dir", 0755), OUTER_CLAMP_ERRNO);

	EXPECT_ERRNO("stat /tmp/ns_test_dir routed to outer clamp",
		     stat("/tmp/ns_test_dir", &st), OUTER_CLAMP_ERRNO);

	EXPECT_ERRNO("access /tmp/ns_test_dir routed to outer clamp",
		     access("/tmp/ns_test_dir", F_OK), OUTER_CLAMP_ERRNO);

	EXPECT_ERRNO("unlink /tmp/ns_test_unlink routed to outer clamp",
		     unlink("/tmp/ns_test_unlink"), OUTER_CLAMP_ERRNO);

	EXPECT_ERRNO("rmdir /tmp/ns_test_dir routed to outer clamp",
		     rmdir("/tmp/ns_test_dir"), OUTER_CLAMP_ERRNO);

	CHECK("stat /dev/null not clamped", stat("/dev/null", &st) == 0);
}

static void test_interleaved_open_routing(void) {
	printf("\n[test_interleaved_open_routing]\n");

	EXPECT_ERRNO("open /tmp/ns_interleave_0 routed to outer clamp",
		     open("/tmp/ns_interleave_0", O_CREAT | O_RDWR, 0644),
		     OUTER_CLAMP_ERRNO);

	int fd = open("/dev/null", O_RDWR);
	CHECK("open /dev/null #1 not clamped", fd >= 0);
	if (fd >= 0)
		close(fd);

	EXPECT_ERRNO("open /tmp/ns_interleave_2 routed to outer clamp",
		     open("/tmp/ns_interleave_2", O_CREAT | O_RDWR, 0644),
		     OUTER_CLAMP_ERRNO);

	fd = open("/dev/null", O_RDWR);
	CHECK("open /dev/null #2 not clamped", fd >= 0);
	if (fd >= 0)
		close(fd);

	EXPECT_ERRNO("open /tmp/ns_interleave_4 routed to outer clamp",
		     open("/tmp/ns_interleave_4", O_CREAT | O_RDWR, 0644),
		     OUTER_CLAMP_ERRNO);

	fd = open("/dev/null", O_RDWR);
	CHECK("open /dev/null #3 not clamped", fd >= 0);
	if (fd >= 0)
		close(fd);
}

static void test_nested_path_routing(void) {
	printf("\n[test_nested_path_routing]\n");

	EXPECT_ERRNO("open /tmp/noninner routed to outer clamp",
		     open("/tmp/noninner", O_CREAT | O_RDWR, 0644),
		     OUTER_CLAMP_ERRNO);

	EXPECT_ERRNO("open /tmp/inner routed to inner clamp",
		     open("/tmp/inner", O_CREAT | O_RDWR, 0644),
		     INNER_CLAMP_ERRNO);

	int fd = open("/dev/null", O_RDWR);
	CHECK("open /dev/null not clamped", fd >= 0);
	if (fd >= 0)
		close(fd);
}

static void test_non_tmp_paths_not_clamped(void) {
	printf("\n[test_non_tmp_paths_not_clamped]\n");

	struct stat st;
	char buf[8] = {0};

	int fd = open("/dev/zero", O_RDONLY);
	CHECK("open /dev/zero not clamped", fd >= 0);
	if (fd >= 0)
		close(fd);

	fd = open("/dev/null", O_WRONLY);
	CHECK("open /dev/null not clamped", fd >= 0);
	if (fd >= 0)
		close(fd);

	CHECK("stat /dev/zero not clamped", stat("/dev/zero", &st) == 0);

	CHECK("access /dev/null not clamped", access("/dev/null", F_OK) == 0);

	fd = open("/dev/zero", O_RDONLY);
	CHECK("read from /dev/zero not clamped",
	      fd >= 0 && read(fd, buf, sizeof(buf)) == (ssize_t)sizeof(buf));
	if (fd >= 0)
		close(fd);
}

int main(int argc, char *argv[]) {
	(void)argc;
	(void)argv;

	printf("=== namespace grate routing test ===\n");

	/* Ensure /tmp itself is seen as clamped. */
	mkdir("/tmp", 0777);

	test_open_routing();
	test_path_syscalls();
	test_interleaved_open_routing();
	test_nested_path_routing();
	test_non_tmp_paths_not_clamped();

	printf("\n=== results: %d/%d passed ===\n", tests_passed, tests_run);
	return (tests_passed == tests_run) ? 0 : 1;
}
