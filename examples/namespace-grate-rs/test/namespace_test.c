/* namespace_test.c — Test binary for the namespace clamping grate.
 *
 * Tests path-prefix routing across a range of syscalls and edge cases.
 *
 * Expected invocation:
 *   lind-wasm namespace-grate.cwasm --prefix /tmp %{ imfs-grate.cwasm %}
 *     namespace_test.cwasm
 *
 * The namespace grate routes /tmp/* operations through IMFS and lets
 * everything else hit the kernel.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>

static int tests_run = 0;
static int tests_passed = 0;

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

/* ── Test 1: Basic clamped open/write/read/close ──────────────────────── */

static void test_open_routing(void) {
	printf("\n[test_open_routing]\n");

	/* Clamped path — should go through IMFS. */
	int fd_tmp = open("/tmp/ns_test_file", O_CREAT | O_RDWR, 0644);
	CHECK("open /tmp/ns_test_file succeeds", fd_tmp >= 0);

	/* Non-clamped path — should go to kernel. */
	int fd_dev = open("/dev/null", O_RDWR);
	CHECK("open /dev/null succeeds", fd_dev >= 0);

	if (fd_tmp >= 0)
		close(fd_tmp);
	if (fd_dev >= 0)
		close(fd_dev);
}

/* ── Test 2: Write/read round-trip on clamped fd ──────────────────────── */

static void test_fd_routing(void) {
	printf("\n[test_fd_routing]\n");

	const char *msg = "hello from namespace test";
	char buf[64] = {0};

	int fd_tmp = open("/tmp/ns_test_rw", O_CREAT | O_RDWR | O_TRUNC, 0644);
	CHECK("open /tmp/ns_test_rw for write", fd_tmp >= 0);

	if (fd_tmp >= 0) {
		ssize_t nw = write(fd_tmp, msg, strlen(msg));
		CHECK("write to clamped fd succeeds",
		      nw == (ssize_t)strlen(msg));

		lseek(fd_tmp, 0, SEEK_SET);
		ssize_t nr = read(fd_tmp, buf, sizeof(buf) - 1);
		CHECK("read from clamped fd succeeds",
		      nr == (ssize_t)strlen(msg));
		CHECK("read data matches written data",
		      memcmp(buf, msg, strlen(msg)) == 0);

		close(fd_tmp);
	}

	/* Non-clamped write — should passthrough to kernel. */
	int fd_dev = open("/dev/null", O_WRONLY);
	if (fd_dev >= 0) {
		ssize_t nw = write(fd_dev, msg, strlen(msg));
		CHECK("write to non-clamped fd succeeds",
		      nw == (ssize_t)strlen(msg));
		close(fd_dev);
	}
}

/* ── Test 3: Dup preserves clamped status ─────────────────────────────── */

static void test_dup_routing(void) {
	printf("\n[test_dup_routing]\n");

	const char *msg = "dup test data";
	char buf[64] = {0};

	int fd_tmp = open("/tmp/ns_test_dup", O_CREAT | O_RDWR | O_TRUNC, 0644);
	CHECK("open /tmp/ns_test_dup", fd_tmp >= 0);

	if (fd_tmp >= 0) {
		int fd_dup = dup(fd_tmp);
		CHECK("dup of clamped fd succeeds", fd_dup >= 0);

		if (fd_dup >= 0) {
			ssize_t nw = write(fd_dup, msg, strlen(msg));
			CHECK("write through dup'd clamped fd",
			      nw == (ssize_t)strlen(msg));

			lseek(fd_tmp, 0, SEEK_SET);
			ssize_t nr = read(fd_tmp, buf, sizeof(buf) - 1);
			CHECK("read back through original fd",
			      nr == (ssize_t)strlen(msg));
			CHECK("data matches after dup write",
			      memcmp(buf, msg, strlen(msg)) == 0);

			close(fd_dup);
		}
		close(fd_tmp);
	}
}

/* ── Test 4: mkdir/stat/access/unlink/rmdir ───────────────────────────── */

static void test_path_syscalls(void) {
	printf("\n[test_path_syscalls]\n");

	int ret = mkdir("/tmp/ns_test_dir", 0755);
	CHECK("mkdir /tmp/ns_test_dir", ret == 0 || errno == EEXIST);

	struct stat st;
	ret = stat("/tmp/ns_test_dir", &st);
	CHECK("stat /tmp/ns_test_dir", ret == 0);

	ret = access("/tmp/ns_test_dir", F_OK);
	CHECK("access /tmp/ns_test_dir", ret == 0);

	int fd = open("/tmp/ns_test_unlink", O_CREAT | O_WRONLY, 0644);
	if (fd >= 0)
		close(fd);
	ret = unlink("/tmp/ns_test_unlink");
	CHECK("unlink /tmp/ns_test_unlink", ret == 0);

	ret = rmdir("/tmp/ns_test_dir");
	CHECK("rmdir /tmp/ns_test_dir", ret == 0);

	/* Non-clamped stat — kernel path. */
	ret = stat("/dev/null", &st);
	CHECK("stat /dev/null (non-clamped, kernel)", ret == 0);
}

/* ── Test 5: Large write spanning multiple IMFS chunks ────────────────── */

static void test_large_write(void) {
	printf("\n[test_large_write]\n");

	/* Write 8000 bytes — should span multiple 1024-byte IMFS chunks. */
	char wbuf[8000];
	for (int i = 0; i < 8000; i++)
		wbuf[i] = 'A' + (i % 26);

	int fd = open("/tmp/ns_test_large", O_CREAT | O_RDWR | O_TRUNC, 0644);
	CHECK("create /tmp/ns_test_large", fd >= 0);
	if (fd < 0)
		return;

	ssize_t nw = write(fd, wbuf, 8000);
	CHECK("write 8000 bytes", nw == 8000);

	lseek(fd, 0, SEEK_SET);

	char rbuf[8000] = {0};
	ssize_t total = 0;
	while (total < 8000) {
		ssize_t nr = read(fd, rbuf + total, 8000 - total);
		if (nr <= 0)
			break;
		total += nr;
	}
	CHECK("read 8000 bytes back", total == 8000);
	CHECK("data matches", memcmp(rbuf, wbuf, 8000) == 0);

	close(fd);
}

/* ── Test 6: Nested directories under clamped prefix ──────────────────── */

static void test_nested_dirs(void) {
	printf("\n[test_nested_dirs]\n");

	mkdir("/tmp/ns_a", 0755);
	mkdir("/tmp/ns_a/ns_b", 0755);
	mkdir("/tmp/ns_a/ns_b/ns_c", 0755);

	int fd = open("/tmp/ns_a/ns_b/ns_c/deep_file", O_CREAT | O_RDWR, 0644);
	CHECK("create deep nested file under /tmp", fd >= 0);

	if (fd >= 0) {
		write(fd, "deep", 4);
		lseek(fd, 0, SEEK_SET);
		char buf[16] = {0};
		ssize_t nr = read(fd, buf, sizeof(buf));
		CHECK("read deep nested file", nr == 4);
		CHECK("data is 'deep'", memcmp(buf, "deep", 4) == 0);
		close(fd);
	}

	unlink("/tmp/ns_a/ns_b/ns_c/deep_file");
	rmdir("/tmp/ns_a/ns_b/ns_c");
	rmdir("/tmp/ns_a/ns_b");
	rmdir("/tmp/ns_a");
}

/* ── Test 7: Multiple files open simultaneously ───────────────────────── */

static void test_multiple_open(void) {
	printf("\n[test_multiple_open]\n");

	int fd1 = open("/tmp/ns_multi_1", O_CREAT | O_RDWR | O_TRUNC, 0644);
	int fd2 = open("/tmp/ns_multi_2", O_CREAT | O_RDWR | O_TRUNC, 0644);
	int fd3 = open("/tmp/ns_multi_3", O_CREAT | O_RDWR | O_TRUNC, 0644);

	CHECK("open 3 clamped files simultaneously", fd1 >= 0 && fd2 >= 0 && fd3 >= 0);

	/* Write different data to each. */
	write(fd1, "file1", 5);
	write(fd2, "file2_longer", 12);
	write(fd3, "f3", 2);

	/* Read each back and verify. */
	char buf[64] = {0};

	lseek(fd1, 0, SEEK_SET);
	ssize_t nr = read(fd1, buf, sizeof(buf));
	CHECK("fd1 has correct data", nr == 5 && memcmp(buf, "file1", 5) == 0);

	lseek(fd2, 0, SEEK_SET);
	nr = read(fd2, buf, sizeof(buf));
	CHECK("fd2 has correct data", nr == 12 && memcmp(buf, "file2_longer", 12) == 0);

	lseek(fd3, 0, SEEK_SET);
	nr = read(fd3, buf, sizeof(buf));
	CHECK("fd3 has correct data", nr == 2 && memcmp(buf, "f3", 2) == 0);

	close(fd1);
	close(fd2);
	close(fd3);
	unlink("/tmp/ns_multi_1");
	unlink("/tmp/ns_multi_2");
	unlink("/tmp/ns_multi_3");
}

/* ── Test 8: Fork child inherits clamped fd state ─────────────────────── */

static void test_fork_inherit(void) {
	printf("\n[test_fork_inherit]\n");

	int fd = open("/tmp/ns_fork_test", O_CREAT | O_RDWR | O_TRUNC, 0644);
	CHECK("create /tmp/ns_fork_test", fd >= 0);
	if (fd < 0)
		return;

	write(fd, "parent wrote", 12);

	pid_t pid = fork();
	if (pid == 0) {
		/* Child: inherited fd should still be clamped and readable. */
		lseek(fd, 0, SEEK_SET);
		char buf[64] = {0};
		ssize_t nr = read(fd, buf, sizeof(buf));

		/* Child writes to a new clamped file to prove routing works. */
		int cfd = open("/tmp/ns_fork_child", O_CREAT | O_WRONLY, 0644);
		if (cfd >= 0) {
			write(cfd, "child wrote", 11);
			close(cfd);
		}

		close(fd);
		_exit((nr == 12 && cfd >= 0) ? 0 : 1);
	}

	int status = 0;
	waitpid(pid, &status, 0);
	CHECK("child exited successfully", WIFEXITED(status) && WEXITSTATUS(status) == 0);

	/* Verify the child's file exists and has correct content. */
	int cfd = open("/tmp/ns_fork_child", O_RDONLY);
	CHECK("open child's clamped file from parent", cfd >= 0);
	if (cfd >= 0) {
		char buf[64] = {0};
		ssize_t nr = read(cfd, buf, sizeof(buf));
		CHECK("child's file has correct data",
		      nr == 11 && memcmp(buf, "child wrote", 11) == 0);
		close(cfd);
	}

	close(fd);
	unlink("/tmp/ns_fork_test");
	unlink("/tmp/ns_fork_child");
}

/* ── Test 9: Clamped and non-clamped open interleaved ─────────────────── */

static void test_interleaved_routing(void) {
	printf("\n[test_interleaved_routing]\n");

	/* Alternate between clamped and non-clamped opens. Verifies the
	 * namespace grate correctly routes each one independently. */
	int fds[6];
	fds[0] = open("/tmp/ns_interleave_0", O_CREAT | O_RDWR, 0644); /* clamped */
	fds[1] = open("/dev/null", O_RDWR);                              /* kernel */
	fds[2] = open("/tmp/ns_interleave_2", O_CREAT | O_RDWR, 0644); /* clamped */
	fds[3] = open("/dev/null", O_RDWR);                              /* kernel */
	fds[4] = open("/tmp/ns_interleave_4", O_CREAT | O_RDWR, 0644); /* clamped */
	fds[5] = open("/dev/null", O_RDWR);                              /* kernel */

	int all_ok = 1;
	for (int i = 0; i < 6; i++) {
		if (fds[i] < 0)
			all_ok = 0;
	}
	CHECK("6 interleaved opens all succeed", all_ok);

	/* Write to clamped fds and verify. */
	write(fds[0], "zero", 4);
	write(fds[2], "two", 3);
	write(fds[4], "four", 4);

	char buf[16] = {0};
	lseek(fds[0], 0, SEEK_SET);
	ssize_t nr = read(fds[0], buf, 16);
	CHECK("clamped fd[0] round-trip", nr == 4 && memcmp(buf, "zero", 4) == 0);

	lseek(fds[2], 0, SEEK_SET);
	nr = read(fds[2], buf, 16);
	CHECK("clamped fd[2] round-trip", nr == 3 && memcmp(buf, "two", 3) == 0);

	lseek(fds[4], 0, SEEK_SET);
	nr = read(fds[4], buf, 16);
	CHECK("clamped fd[4] round-trip", nr == 4 && memcmp(buf, "four", 4) == 0);

	/* Non-clamped writes should succeed (to /dev/null). */
	ssize_t nw = write(fds[1], "x", 1);
	CHECK("non-clamped fd[1] write succeeds", nw == 1);

	for (int i = 0; i < 6; i++)
		close(fds[i]);

	unlink("/tmp/ns_interleave_0");
	unlink("/tmp/ns_interleave_2");
	unlink("/tmp/ns_interleave_4");
}

/* ── Test 10: Overwrite and re-read ───────────────────────────────────── */

static void test_overwrite(void) {
	printf("\n[test_overwrite]\n");

	int fd = open("/tmp/ns_overwrite", O_CREAT | O_RDWR | O_TRUNC, 0644);
	CHECK("create /tmp/ns_overwrite", fd >= 0);
	if (fd < 0)
		return;

	/* Write initial data. */
	write(fd, "original", 8);

	/* Seek to beginning and overwrite with shorter data. */
	lseek(fd, 0, SEEK_SET);
	write(fd, "new", 3);

	/* Read from beginning — should see "newginal" (overwrite, not truncate). */
	lseek(fd, 0, SEEK_SET);
	char buf[64] = {0};
	ssize_t nr = read(fd, buf, sizeof(buf));
	CHECK("overwrite preserves remaining bytes",
	      nr == 8 && memcmp(buf, "newginal", 8) == 0);

	close(fd);
	unlink("/tmp/ns_overwrite");
}

/* ── Test 11: lseek with SEEK_SET, SEEK_CUR, SEEK_END ────────────────── */

static void test_lseek(void) {
	printf("\n[test_lseek]\n");

	int fd = open("/tmp/ns_lseek", O_CREAT | O_RDWR | O_TRUNC, 0644);
	CHECK("create /tmp/ns_lseek", fd >= 0);
	if (fd < 0)
		return;

	write(fd, "0123456789", 10);

	off_t pos = lseek(fd, 5, SEEK_SET);
	CHECK("SEEK_SET to 5", pos == 5);

	pos = lseek(fd, 2, SEEK_CUR);
	CHECK("SEEK_CUR +2 = 7", pos == 7);

	pos = lseek(fd, -3, SEEK_END);
	CHECK("SEEK_END -3 = 7", pos == 7);

	char buf[4] = {0};
	ssize_t nr = read(fd, buf, 3);
	CHECK("read 3 bytes from pos 7", nr == 3);
	CHECK("data is '789'", memcmp(buf, "789", 3) == 0);

	close(fd);
	unlink("/tmp/ns_lseek");
}

/* ── Test 12: Open nonexistent clamped file without O_CREAT ───────────── */

static void test_open_nonexistent(void) {
	printf("\n[test_open_nonexistent]\n");

	int fd = open("/tmp/ns_does_not_exist_98765", O_RDONLY);
	CHECK("open nonexistent clamped path fails", fd < 0);
}

/* ── Test 13: Dup2 of clamped fd to specific number ───────────────────── */

static void test_dup2(void) {
	printf("\n[test_dup2]\n");

	int fd = open("/tmp/ns_dup2_test", O_CREAT | O_RDWR | O_TRUNC, 0644);
	CHECK("create /tmp/ns_dup2_test", fd >= 0);
	if (fd < 0)
		return;

	int ret = dup2(fd, 50);
	CHECK("dup2 to fd 50", ret == 50);

	write(50, "via dup2", 8);
	lseek(fd, 0, SEEK_SET);

	char buf[16] = {0};
	ssize_t nr = read(fd, buf, sizeof(buf));
	CHECK("read through original after dup2 write", nr == 8);
	CHECK("data matches", memcmp(buf, "via dup2", 8) == 0);

	close(50);
	close(fd);
	unlink("/tmp/ns_dup2_test");
}

/* ── Main ──────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[]) {
	printf("=== namespace grate test ===\n");

	/* Ensure /tmp exists in IMFS. */
	mkdir("/tmp", 0777);

	test_open_routing();
	test_fd_routing();
	test_dup_routing();
	test_path_syscalls();
	test_large_write();
	test_nested_dirs();
	test_multiple_open();
	test_fork_inherit();
	test_interleaved_routing();
	test_overwrite();
	test_lseek();
	test_open_nonexistent();
	test_dup2();

	printf("\n=== results: %d/%d passed ===\n", tests_passed, tests_run);
	return (tests_passed == tests_run) ? 0 : 1;
}
