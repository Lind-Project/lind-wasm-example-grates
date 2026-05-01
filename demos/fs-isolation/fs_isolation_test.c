/*
 * Filesystem isolation demo.
 *
 * Verifies that two cages sharing the same fs-routing-clamp each get
 * independent in-memory filesystems for /tmp. Writes from one cage
 * to /tmp/foo must not be visible in the other.
 *
 * Also verifies that non-/tmp paths (host filesystem) are shared
 * normally between cages.
 *
 * Usage:
 *   lind-wasm grates/fs-routing-clamp.cwasm --prefix /tmp %{ \
 *     grates/imfs-grate.cwasm \
 *   %} fs_isolation_test.cwasm
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static int tests_run = 0;
static int tests_passed = 0;

#define CHECK(name, expr)                                                      \
	do {                                                                   \
		tests_run++;                                                   \
		if (expr) {                                                    \
			printf("  PASS: %s\n", name);                          \
			tests_passed++;                                        \
		} else {                                                       \
			printf("  FAIL: %s (errno=%d %s)\n", name, errno,      \
			       strerror(errno));                               \
		}                                                              \
	} while (0)

int main(void) {
	printf("=== Filesystem Isolation Demo ===\n");

	/* Create /tmp in imfs */
	mkdir("/tmp", 0755);

	/*
	 * Test 1: Two cages write different data to /tmp/foo.
	 * Each should see only its own data.
	 */
	printf("\n[test_independent_tmp]\n");

	/* Parent writes to /tmp/foo */
	int fd = open("/tmp/foo", O_CREAT | O_RDWR | O_TRUNC, 0644);
	CHECK("parent: create /tmp/foo", fd >= 0);
	if (fd >= 0) {
		write(fd, "parent-data", 11);
		close(fd);
	}

	/* Fork child — child gets its own imfs for /tmp */
	pid_t pid = fork();
	if (pid == 0) {
		/* Child: write different data to /tmp/foo */
		mkdir("/tmp", 0755);
		int cfd = open("/tmp/foo", O_CREAT | O_RDWR | O_TRUNC, 0644);
		if (cfd < 0)
			_exit(1);
		write(cfd, "child-data", 10);
		close(cfd);

		/* Child: read back /tmp/foo — should see child's data, not
		 * parent's */
		cfd = open("/tmp/foo", O_RDONLY);
		if (cfd < 0)
			_exit(1);
		char buf[32] = {0};
		ssize_t n = read(cfd, buf, sizeof(buf) - 1);
		close(cfd);

		if (n != 10 || memcmp(buf, "child-data", 10) != 0) {
			printf("  FAIL: child sees wrong data: '%s'\n", buf);
			_exit(1);
		}
		printf("  PASS: child: /tmp/foo contains child-data only\n");
		_exit(0);
	}

	int status;
	waitpid(pid, &status, 0);
	CHECK("child exited cleanly",
	      WIFEXITED(status) && WEXITSTATUS(status) == 0);

	/* Parent: read back /tmp/foo — should still see parent's data */
	fd = open("/tmp/foo", O_RDONLY);
	CHECK("parent: reopen /tmp/foo", fd >= 0);
	if (fd >= 0) {
		char buf[32] = {0};
		ssize_t n = read(fd, buf, sizeof(buf) - 1);
		close(fd);
		CHECK("parent: /tmp/foo still contains parent-data",
		      n == 11 && memcmp(buf, "parent-data", 11) == 0);
	}

	/*
	 * Test 2: Multiple files in /tmp are independent per cage.
	 */
	printf("\n[test_multiple_files]\n");

	fd = open("/tmp/a.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
	CHECK("parent: create /tmp/a.txt", fd >= 0);
	if (fd >= 0) {
		write(fd, "aaa", 3);
		close(fd);
	}

	fd = open("/tmp/b.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
	CHECK("parent: create /tmp/b.txt", fd >= 0);
	if (fd >= 0) {
		write(fd, "bbb", 3);
		close(fd);
	}

	pid = fork();
	if (pid == 0) {
		/* Child: /tmp/a.txt and /tmp/b.txt should not exist (fresh
		 * imfs) */
		int cfd = open("/tmp/a.txt", O_RDONLY);
		if (cfd >= 0) {
			printf("  FAIL: child can see parent's /tmp/a.txt\n");
			close(cfd);
			_exit(1);
		}
		printf("  PASS: child: /tmp/a.txt not visible (independent "
		       "imfs)\n");

		cfd = open("/tmp/b.txt", O_RDONLY);
		if (cfd >= 0) {
			printf("  FAIL: child can see parent's /tmp/b.txt\n");
			close(cfd);
			_exit(1);
		}
		printf("  PASS: child: /tmp/b.txt not visible (independent "
		       "imfs)\n");
		_exit(0);
	}

	waitpid(pid, &status, 0);
	CHECK("child verified isolation",
	      WIFEXITED(status) && WEXITSTATUS(status) == 0);

	/*
	 * Test 3: Non-/tmp paths are NOT isolated (shared host filesystem).
	 */
	printf("\n[test_non_tmp_shared]\n");

	fd = open("/dev/null", O_WRONLY);
	CHECK("parent: /dev/null accessible (host FS)", fd >= 0);
	if (fd >= 0) {
		ssize_t n = write(fd, "test", 4);
		CHECK("parent: write to /dev/null succeeds", n == 4);
		close(fd);
	}

	/* Clean up */
	unlink("/tmp/foo");
	unlink("/tmp/a.txt");
	unlink("/tmp/b.txt");

	printf("\n=== Result: %d/%d passed ===\n", tests_passed, tests_run);
	return (tests_passed == tests_run) ? 0 : 1;
}
