/* crypt_test.c - end-to-end test for crypt-grate under fs-routing-clamp.
 *
 * Files under /tmp/crypt go through crypt-grate. To check what actually lands
 * on disk, the test hard-links an encrypted file to a path outside the prefix
 * and reads the raw bytes through that link.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#define DIR "/tmp/crypt"
#define RAW_LINK "/tmp/raw-view-of-crypt-test"

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

static void fill_pattern(unsigned char *buf, size_t n, unsigned seed)
{
	for (size_t i = 0; i < n; i++)
		buf[i] = (unsigned char)((i * 131 + seed * 7 + (i >> 8)) & 0xff);
}

static off_t file_size(const char *path)
{
	struct stat st;
	return stat(path, &st) == 0 ? st.st_size : -1;
}

static void test_roundtrip(void)
{
	printf("[roundtrip]\n");
	const char *path = DIR "/notes.txt";
	FILE *f = fopen(path, "w");
	CHECK("fopen for writing", f != NULL);
	if (!f)
		return;
	for (int i = 0; i < 500; i++)
		fprintf(f, "line %03d: the eagle has landed\n", i);
	fclose(f);

	f = fopen(path, "r");
	CHECK("fopen for reading", f != NULL);
	if (!f)
		return;
	char line[128];
	int ok = 1, n = 0;
	while (fgets(line, sizeof line, f)) {
		char want[128];
		snprintf(want, sizeof want, "line %03d: the eagle has landed\n", n);
		if (strcmp(line, want) != 0)
			ok = 0;
		n++;
	}
	fclose(f);
	CHECK("all 500 lines read back in order", ok && n == 500);
	CHECK("stat reports the plaintext size", file_size(path) == 500 * 31);
}

static void test_binary_random_access(void)
{
	printf("[binary data, random access]\n");
	const char *path = DIR "/blob.bin";
	enum { N = 20000 };
	static unsigned char data[N], back[N];
	fill_pattern(data, N, 1);
	data[0] = 0; /* zero bytes must survive the copies */
	data[5000] = 0;

	int fd = open(path, O_CREAT | O_TRUNC | O_RDWR, 0600);
	CHECK("open O_RDWR|O_CREAT", fd >= 0);
	if (fd < 0)
		return;
	CHECK("write 20000 bytes", write(fd, data, N) == N);
	CHECK("offset is plaintext offset", lseek(fd, 0, SEEK_CUR) == N);
	CHECK("SEEK_END is plaintext size", lseek(fd, 0, SEEK_END) == N);

	/* Overwrite a span crossing the 4096-byte block boundary. */
	unsigned char patch[40];
	memset(patch, 'Z', sizeof patch);
	CHECK("pwrite across a block boundary",
	      pwrite(fd, patch, sizeof patch, 4080) == sizeof patch);
	memcpy(data + 4080, patch, sizeof patch);

	CHECK("pread whole file", pread(fd, back, N, 0) == N);
	CHECK("contents match", memcmp(back, data, N) == 0);

	struct stat st;
	CHECK("fstat size", fstat(fd, &st) == 0 && st.st_size == N);

	/* Seek past the end and write: the gap reads as zeros. */
	CHECK("seek past EOF", lseek(fd, N + 100, SEEK_SET) == N + 100);
	CHECK("write after gap", write(fd, "end", 3) == 3);
	unsigned char gap[103];
	CHECK("read gap", pread(fd, gap, sizeof gap, N) == sizeof gap);
	int zeros = 1;
	for (int i = 0; i < 100; i++)
		if (gap[i] != 0)
			zeros = 0;
	CHECK("gap is zero-filled", zeros && memcmp(gap + 100, "end", 3) == 0);

	/* readv/writev */
	char a[5], b[7];
	/* Designated initializers: Lind's struct iovec has padding fields between
	 * iov_base and iov_len, so positional initializers would set the padding. */
	struct iovec wv[2] = {{.iov_base = "hello", .iov_len = 5},
			      {.iov_base = ", world", .iov_len = 7}};
	struct iovec rv[2] = {{.iov_base = a, .iov_len = 5},
			      {.iov_base = b, .iov_len = 7}};
	CHECK("pwritev", pwritev(fd, wv, 2, 10) == 12);
	CHECK("preadv", preadv(fd, rv, 2, 10) == 12);
	CHECK("vectored data matches",
	      memcmp(a, "hello", 5) == 0 && memcmp(b, ", world", 7) == 0);
	close(fd);
}

static void test_append(void)
{
	printf("[append]\n");
	const char *path = DIR "/log.txt";
	unlink(path);
	for (int i = 0; i < 3; i++) {
		FILE *f = fopen(path, "a");
		if (!f)
			break;
		fprintf(f, "entry %d\n", i);
		fclose(f);
	}
	int fd = open(path, O_WRONLY | O_APPEND);
	CHECK("F_GETFL shows O_APPEND", fd >= 0 && (fcntl(fd, F_GETFL) & O_APPEND));
	lseek(fd, 0, SEEK_SET);
	CHECK("write after seek(0) still appends", write(fd, "entry 3\n", 8) == 8);
	close(fd);

	char buf[64] = {0};
	fd = open(path, O_RDONLY);
	CHECK("read log", fd >= 0 && read(fd, buf, sizeof buf - 1) == 32);
	close(fd);
	CHECK("log contents in order",
	      strcmp(buf, "entry 0\nentry 1\nentry 2\nentry 3\n") == 0);
}

static void test_truncate(void)
{
	printf("[truncate]\n");
	const char *path = DIR "/trunc.bin";
	enum { N = 10000 };
	static unsigned char data[N], back[N];
	fill_pattern(data, N, 2);
	int fd = open(path, O_CREAT | O_TRUNC | O_RDWR, 0600);
	if (fd < 0) {
		CHECK("open", 0);
		return;
	}
	CHECK("write", write(fd, data, N) == N);
	CHECK("ftruncate shrink mid-block", ftruncate(fd, 5000) == 0);
	CHECK("size after shrink", file_size(path) == 5000);
	CHECK("ftruncate grow", ftruncate(fd, 6000) == 0);
	memset(back, 0xEE, sizeof back);
	CHECK("read after grow", pread(fd, back, N, 0) == 6000);
	int ok = memcmp(back, data, 5000) == 0;
	for (int i = 5000; i < 6000; i++)
		if (back[i] != 0)
			ok = 0;
	CHECK("kept prefix, zero tail", ok);
	close(fd);
	CHECK("truncate by path", truncate(path, 100) == 0 && file_size(path) == 100);
	CHECK("truncate to zero", truncate(path, 0) == 0 && file_size(path) == 0);
}

static void test_fork_shares_offset(void)
{
	printf("[fork]\n");
	const char *path = DIR "/shared.txt";
	int fd = open(path, O_CREAT | O_TRUNC | O_RDWR, 0600);
	if (fd < 0) {
		CHECK("open", 0);
		return;
	}
	CHECK("parent write before fork", write(fd, "parent-", 7) == 7);
	pid_t pid = fork();
	if (pid == 0) {
		_exit(write(fd, "child-", 6) == 6 ? 0 : 1);
	}
	int status = 0;
	waitpid(pid, &status, 0);
	CHECK("child exited cleanly", WIFEXITED(status) && WEXITSTATUS(status) == 0);
	CHECK("offset advanced by the child", lseek(fd, 0, SEEK_CUR) == 13);
	CHECK("parent write after child", write(fd, "parent", 6) == 6);
	char buf[32] = {0};
	CHECK("pread shared file", pread(fd, buf, sizeof buf - 1, 0) == 19);
	CHECK("interleaved writes", strcmp(buf, "parent-child-parent") == 0);
	close(fd);
}

static void test_on_disk_is_ciphertext(void)
{
	printf("[on-disk format]\n");
	const char *path = DIR "/notes.txt";
	unlink(RAW_LINK);
	if (link(path, RAW_LINK) != 0) {
		CHECK("hard link to a path outside the prefix", 0);
		return;
	}
	static char raw[32768];
	int fd = open(RAW_LINK, O_RDONLY);
	ssize_t n = fd >= 0 ? read(fd, raw, sizeof raw) : -1;
	if (fd >= 0)
		close(fd);
	CHECK("raw file readable outside the prefix", n > 0);
	CHECK("raw file starts with the LCRY header", n >= 4 && memcmp(raw, "LCRY", 4) == 0);
	int leaked = 0;
	for (ssize_t i = 0; i + 5 <= n; i++)
		if (memcmp(raw + i, "eagle", 5) == 0)
			leaked = 1;
	CHECK("no plaintext on disk", !leaked);
	CHECK("raw file is larger than the plaintext", n > 500 * 31);
	unlink(RAW_LINK);
}

static void test_mmap_refused(void)
{
	printf("[mmap]\n");
	int fd = open(DIR "/blob.bin", O_RDONLY);
	void *p = fd >= 0 ? mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0) : MAP_FAILED;
	CHECK("file-backed mmap of an encrypted file fails with ENODEV",
	      p == MAP_FAILED && errno == ENODEV);
	if (p != MAP_FAILED)
		munmap(p, 4096);
	if (fd >= 0)
		close(fd);
}

static void cleanup(void)
{
	const char *files[] = {"notes.txt", "blob.bin", "log.txt", "trunc.bin", "shared.txt"};
	char path[64];
	for (size_t i = 0; i < sizeof files / sizeof *files; i++) {
		snprintf(path, sizeof path, DIR "/%s", files[i]);
		unlink(path);
	}
	unlink(RAW_LINK);
	rmdir(DIR);
}

int main(void)
{
	cleanup();
	mkdir(DIR, 0755);
	printf("crypt-grate test\n");
	test_roundtrip();
	test_binary_random_access();
	test_append();
	test_truncate();
	test_fork_shares_offset();
	test_on_disk_is_ciphertext();
	test_mmap_refused();
	cleanup();
	printf("\n%d/%d tests passed\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
