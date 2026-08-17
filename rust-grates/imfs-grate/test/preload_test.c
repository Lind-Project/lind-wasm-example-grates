#define _GNU_SOURCE

/* preload_test.c — Test binary for the Rust IMFS grate's PRELOADS staging.
 *
 * The grate reads PRELOADS before the cage is forked and stages each host file
 * into IMFS under utility cage 0. This binary runs as the child cage (a
 * different cage id) and checks that the staged files are visible and correct
 * from there.
 *
 * The PRELOADS value used by the test suite (see test/grates_test.toml) is:
 *
 *   /preload_hello.txt=preload_hello.txt
 *   /preload/nested/data.txt=preload_nested.txt
 *   sub/rel.txt=preload_rel.txt
 *   /trunc.txt=preload_long.txt
 *   /trunc.txt=preload_short.txt
 *   (plus an empty entry, "=preload_rel.txt" and "preload_rel.txt=" to check
 *    malformed entries are skipped without aborting the rest of the list)
 *
 * Each test prints PASS/FAIL. Exit code 0 if all tests pass, 1 otherwise.
 */
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
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

/* Read a whole file into buf and NUL-terminate it. Returns the byte count, or
 * -1 if the file could not be opened or read. */
static ssize_t read_all(const char *path, char *buf, size_t bufsz) {
	int fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;

	size_t total = 0;
	while (total < bufsz - 1) {
		ssize_t nr = read(fd, buf + total, bufsz - 1 - total);
		if (nr < 0) {
			close(fd);
			return -1;
		}
		if (nr == 0)
			break;
		total += (size_t)nr;
	}

	close(fd);
	buf[total] = '\0';
	return (ssize_t)total;
}

/*  Test 1: A bare absolute mapping is staged with the exact host contents  */

static void test_preload_absolute(void) {
	printf("\n[test_preload_absolute]\n");

	const char *expected = "hello from the host\n";
	char buf[64] = {0};

	ssize_t n = read_all("/preload_hello.txt", buf, sizeof(buf));
	CHECK("open+read /preload_hello.txt", n >= 0);
	CHECK("contents match host file", n >= 0 && strcmp(buf, expected) == 0);

	struct stat st;
	int ret = stat("/preload_hello.txt", &st);
	CHECK("stat /preload_hello.txt", ret == 0);
	CHECK("preloaded path is a regular file", ret == 0 && S_ISREG(st.st_mode));
	CHECK("st_size matches host file",
	      ret == 0 && st.st_size == (off_t)strlen(expected));
}

/*  Test 2: Missing parent directories are created, and the final component
 *  stays a file rather than being created as a directory  */

static void test_preload_creates_parent_dirs(void) {
	printf("\n[test_preload_creates_parent_dirs]\n");

	const char *expected = "nested payload\n";
	char buf[64] = {0};
	struct stat st;

	int ret = stat("/preload", &st);
	CHECK("stat /preload", ret == 0);
	CHECK("/preload is a directory", ret == 0 && S_ISDIR(st.st_mode));

	ret = stat("/preload/nested", &st);
	CHECK("stat /preload/nested", ret == 0);
	CHECK("/preload/nested is a directory", ret == 0 && S_ISDIR(st.st_mode));

	ret = stat("/preload/nested/data.txt", &st);
	CHECK("stat /preload/nested/data.txt", ret == 0);
	CHECK("final component is a regular file, not a directory",
	      ret == 0 && S_ISREG(st.st_mode));

	ssize_t n = read_all("/preload/nested/data.txt", buf, sizeof(buf));
	CHECK("open+read /preload/nested/data.txt", n >= 0);
	CHECK("nested contents match host file",
	      n >= 0 && strcmp(buf, expected) == 0);
}

/*  Test 3: A relative IMFS path with a parent component resolves against the
 *  cage's cwd, and its final component is not turned into a directory  */

static void test_preload_relative_path(void) {
	printf("\n[test_preload_relative_path]\n");

	const char *expected = "relative payload\n";
	char buf[64] = {0};
	struct stat st;

	int ret = stat("/sub", &st);
	CHECK("stat /sub", ret == 0);
	CHECK("/sub is a directory", ret == 0 && S_ISDIR(st.st_mode));

	ret = stat("/sub/rel.txt", &st);
	CHECK("stat /sub/rel.txt", ret == 0);
	CHECK("relative preload target is a regular file",
	      ret == 0 && S_ISREG(st.st_mode));

	ssize_t n = read_all("/sub/rel.txt", buf, sizeof(buf));
	CHECK("open+read /sub/rel.txt", n >= 0);
	CHECK("relative preload contents match host file",
	      n >= 0 && strcmp(buf, expected) == 0);

	/* The same path reached relatively from the cage's cwd ("/"). */
	n = read_all("sub/rel.txt", buf, sizeof(buf));
	CHECK("open+read sub/rel.txt relative to cwd", n >= 0);
	CHECK("relative lookup returns the same contents",
	      n >= 0 && strcmp(buf, expected) == 0);
}

/*  Test 4: Preloading the same IMFS path twice leaves only the later file's
 *  contents, with no trailing bytes from the earlier one  */

static void test_preload_overwrite_truncates(void) {
	printf("\n[test_preload_overwrite_truncates]\n");

	const char *expected = "BBBB\n";
	char buf[64] = {0};

	ssize_t n = read_all("/trunc.txt", buf, sizeof(buf));
	CHECK("open+read /trunc.txt", n >= 0);
	CHECK("re-preloaded file has no leftover bytes",
	      n == (ssize_t)strlen(expected));
	CHECK("re-preloaded contents match the later host file",
	      n >= 0 && strcmp(buf, expected) == 0);

	struct stat st;
	int ret = stat("/trunc.txt", &st);
	CHECK("stat /trunc.txt", ret == 0);
	CHECK("st_size matches the later host file",
	      ret == 0 && st.st_size == (off_t)strlen(expected));
}

/*  Test 5: Malformed entries are skipped, and paths that were never preloaded
 *  are still absent  */

static void test_preload_skips_bad_entries(void) {
	printf("\n[test_preload_skips_bad_entries]\n");

	errno = 0;
	int fd = open("/preload_missing.txt", O_RDONLY);
	CHECK("open of a non-preloaded path fails", fd < 0);
	CHECK("non-preloaded path reports ENOENT", fd < 0 && errno == ENOENT);
	if (fd >= 0)
		close(fd);

	/* The list contains "=preload_rel.txt" and "preload_rel.txt=". Treating
	 * either as a bare path would stage the host file at /preload_rel.txt,
	 * so that path must stay absent. */
	errno = 0;
	fd = open("/preload_rel.txt", O_RDONLY);
	CHECK("malformed entry is not treated as a bare path", fd < 0);
	CHECK("malformed entry leaves no stray file", fd < 0 && errno == ENOENT);
	if (fd >= 0)
		close(fd);

	/* /trunc.txt is listed after the malformed entries, so its contents
	 * (checked above) also prove parsing continued past them. */
	struct stat st;
	CHECK("entries after a malformed one are still staged",
	      stat("/trunc.txt", &st) == 0);
}

int main(void) {
	printf("=== imfs grate preload test ===\n");

	test_preload_absolute();
	test_preload_creates_parent_dirs();
	test_preload_relative_path();
	test_preload_overwrite_truncates();
	test_preload_skips_bad_entries();

	printf("\n=== results: %d/%d passed ===\n", tests_passed, tests_run);
	return (tests_passed == tests_run) ? 0 : 1;
}
