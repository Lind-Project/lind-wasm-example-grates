/* namespace_test.c - routing-only tests for the namespace clamping grate.
 *
 * These tests assume clamped FS syscalls are stubbed to a fixed return value.
 * We only verify that:
 *   - syscalls on /tmp/ are routed to the clamp, and
 *   - syscalls on non-/tmp paths are not.
 *
 * Example invocation:
 *      lind-boot fs-routing-clamp.cwasm --prefix /tmp %{ testing-grate.cwasm
 * -s 0:166,1:166,2:166,4:166,21:166,83:166,84:166,87:166 %}
 * namespace_test.cwasm
 *
 * 	We use testing-grate to stub out all FS related syscalls to NS_CLAMP_RET
 * (166). Any calls to /tmp should return this value, all other calls should
 * execute regularly.
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

#define NS_CLAMP_RET 166

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

#define EXPECT_CLAMP(desc, expr) CHECK(desc, ((expr) == NS_CLAMP_RET))
#define EXPECT_NOT_CLAMP(desc, expr) CHECK(desc, ((expr) != NS_CLAMP_RET))

static void test_open_routing(void) {
	printf("\n[test_open_routing]\n");

	EXPECT_CLAMP("open /tmp/ns_test_file routed to clamp",
		     open("/tmp/ns_test_file", O_CREAT | O_RDWR, 0644));

	EXPECT_NOT_CLAMP("open /dev/null not clamped",
			 open("/dev/null", O_RDWR));
}

static void test_rw_routing(void) {
	printf("\n[test_rw_routing]\n");

	int fd_tmp = open("/tmp/ns_test", O_CREAT | O_RDWR | O_TRUNC, 0644);
	CHECK("open /tmp/ns_test routed to clamp", fd_tmp == NS_CLAMP_RET);

	EXPECT_CLAMP("write on clamped fd routed to clamp",
		     write(fd_tmp, "hello", 5));

	char buf[16] = {0};
	EXPECT_CLAMP("read on clamped fd routed to clamp",
		     read(fd_tmp, buf, 5));

	int fd_zero = open("/dev/zero", O_RDONLY);
	EXPECT_NOT_CLAMP("read /dev/zero not clamped", read(fd_zero, buf, 5));
	if (fd_zero >= 0)
		close(fd_zero);

	int fd_null = open("/dev/null", O_WRONLY);
	EXPECT_NOT_CLAMP("write /dev/null not clamped",
			 write(fd_null, "hello", 5));
	if (fd_null >= 0)
		close(fd_null);
}

static void test_path_syscalls(void) {
	printf("\n[test_path_syscalls]\n");

	struct stat st;

	EXPECT_CLAMP("mkdir /tmp/ns_test_dir routed to clamp",
		     mkdir("/tmp/ns_test_dir", 0755));

	EXPECT_CLAMP("stat /tmp/ns_test_dir routed to clamp",
		     stat("/tmp/ns_test_dir", &st));

	EXPECT_CLAMP("access /tmp/ns_test_dir routed to clamp",
		     access("/tmp/ns_test_dir", F_OK));

	EXPECT_CLAMP("unlink /tmp/ns_test_unlink routed to clamp",
		     unlink("/tmp/ns_test_unlink"));

	EXPECT_CLAMP("rmdir /tmp/ns_test_dir routed to clamp",
		     rmdir("/tmp/ns_test_dir"));

	EXPECT_NOT_CLAMP("stat /dev/null not clamped", stat("/dev/null", &st));
}

static void test_interleaved_open_routing(void) {
	printf("\n[test_interleaved_open_routing]\n");

	EXPECT_CLAMP("open /tmp/ns_interleave_0 routed to clamp",
		     open("/tmp/ns_interleave_0", O_CREAT | O_RDWR, 0644));

	EXPECT_NOT_CLAMP("open /dev/null #1 not clamped",
			 open("/dev/null", O_RDWR));

	EXPECT_CLAMP("open /tmp/ns_interleave_2 routed to clamp",
		     open("/tmp/ns_interleave_2", O_CREAT | O_RDWR, 0644));

	EXPECT_NOT_CLAMP("open /dev/null #2 not clamped",
			 open("/dev/null", O_RDWR));

	EXPECT_CLAMP("open /tmp/ns_interleave_4 routed to clamp",
		     open("/tmp/ns_interleave_4", O_CREAT | O_RDWR, 0644));

	EXPECT_NOT_CLAMP("open /dev/null #3 not clamped",
			 open("/dev/null", O_RDWR));
}

static void test_nested_path_routing(void) {
	printf("\n[test_nested_path_routing]\n");

	EXPECT_CLAMP("mkdir /tmp/ns_a routed to clamp",
		     mkdir("/tmp/ns_a", 0755));

	EXPECT_CLAMP("mkdir /tmp/ns_a/ns_b routed to clamp",
		     mkdir("/tmp/ns_a/ns_b", 0755));

	EXPECT_CLAMP("mkdir /tmp/ns_a/ns_b/ns_c routed to clamp",
		     mkdir("/tmp/ns_a/ns_b/ns_c", 0755));

	EXPECT_CLAMP(
	    "open deep /tmp path routed to clamp",
	    open("/tmp/ns_a/ns_b/ns_c/deep_file", O_CREAT | O_RDWR, 0644));

	EXPECT_CLAMP("unlink deep /tmp path routed to clamp",
		     unlink("/tmp/ns_a/ns_b/ns_c/deep_file"));

	EXPECT_CLAMP("rmdir /tmp/ns_a/ns_b/ns_c routed to clamp",
		     rmdir("/tmp/ns_a/ns_b/ns_c"));

	EXPECT_CLAMP("rmdir /tmp/ns_a/ns_b routed to clamp",
		     rmdir("/tmp/ns_a/ns_b"));

	EXPECT_CLAMP("rmdir /tmp/ns_a routed to clamp", rmdir("/tmp/ns_a"));
}

static void test_non_tmp_paths_not_clamped(void) {
	printf("\n[test_non_tmp_paths_not_clamped]\n");

	struct stat st;
	char buf[8] = {0};

	EXPECT_NOT_CLAMP("open /dev/zero not clamped",
			 open("/dev/zero", O_RDONLY));

	EXPECT_NOT_CLAMP("open /dev/null not clamped",
			 open("/dev/null", O_WRONLY));

	EXPECT_NOT_CLAMP("stat /dev/zero not clamped", stat("/dev/zero", &st));

	EXPECT_NOT_CLAMP("access /dev/null not clamped",
			 access("/dev/null", F_OK));

	int fd = open("/dev/zero", O_RDONLY);
	EXPECT_NOT_CLAMP("read from /dev/zero not clamped",
			 read(fd, buf, sizeof(buf)));
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
	test_rw_routing();
	test_path_syscalls();
	test_interleaved_open_routing();
	test_nested_path_routing();
	test_non_tmp_paths_not_clamped();

	printf("\n=== results: %d/%d passed ===\n", tests_passed, tests_run);
	return (tests_passed == tests_run) ? 0 : 1;
}
