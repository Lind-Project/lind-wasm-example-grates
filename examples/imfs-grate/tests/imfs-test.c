#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

#define PASS()                                                                 \
	do {                                                                   \
		printf("PASS: %s\n", __func__);                                \
		total_tests++;                                                 \
	} while (0)

#define FAIL(msg)                                                              \
	do {                                                                   \
		printf("FAIL: %s - %s\n", __func__, msg);                      \
		failures++;                                                    \
		return 1;                                                      \
	} while (0)

static int total_tests = 0;
static int failures = 0;

int test_basic_write_read() {
	int fd = open("test1.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
	if (fd < 0)
		FAIL("open create");

	char wbuf[] = "Hello";
	if (write(fd, wbuf, 5) != 5)
		FAIL("write");
	if (close(fd) != 0)
		FAIL("close after write");

	fd = open("test1.txt", O_RDONLY);
	if (fd < 0)
		FAIL("open readonly");

	char rbuf[6] = {0};
	if (read(fd, rbuf, 5) != 5)
		FAIL("read");
	if (strcmp(rbuf, "Hello") != 0)
		FAIL("data mismatch");
	if (close(fd) != 0)
		FAIL("close after read");

	unlink("test1.txt");
	PASS();
	return 0;
}

int test_multiple_writes() {
	int fd = open("test2.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
	if (fd < 0)
		FAIL("open");

	if (write(fd, "First ", 6) != 6)
		FAIL("write 1");
	if (write(fd, "Second ", 7) != 7)
		FAIL("write 2");
	if (write(fd, "Third", 5) != 5)
		FAIL("write 3");
	close(fd);

	fd = open("test2.txt", O_RDONLY);
	char buf[20] = {0};
	if (read(fd, buf, 18) != 18)
		FAIL("read");
	if (strcmp(buf, "First Second Third") != 0)
		FAIL("content mismatch");
	close(fd);

	unlink("test2.txt");
	PASS();
	return 0;
}

int test_partial_reads() {
	int fd = open("test3.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
	if (fd < 0)
		FAIL("open");

	char data[] = "0123456789";
	if (write(fd, data, 10) != 10)
		FAIL("write");
	close(fd);

	fd = open("test3.txt", O_RDONLY);
	char buf1[5], buf2[5], buf3[5];
	if (read(fd, buf1, 3) != 3)
		FAIL("read 1");
	if (read(fd, buf2, 4) != 4)
		FAIL("read 2");
	if (read(fd, buf3, 3) != 3)
		FAIL("read 3");

	if (memcmp(buf1, "012", 3) != 0)
		FAIL("chunk 1");
	if (memcmp(buf2, "3456", 4) != 0)
		FAIL("chunk 2");
	if (memcmp(buf3, "789", 3) != 0)
		FAIL("chunk 3");
	close(fd);

	unlink("test3.txt");
	PASS();
	return 0;
}

int test_read_past_eof() {
	int fd = open("test4.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
	if (fd < 0)
		FAIL("open");

	write(fd, "short", 5);
	close(fd);

	fd = open("test4.txt", O_RDONLY);
	char buf[100];
	ssize_t n = read(fd, buf, 100);
	if (n != 5)
		FAIL("read past EOF should return actual bytes");

	n = read(fd, buf, 100);
	if (n != 0)
		FAIL("read at EOF should return 0");
	close(fd);

	unlink("test4.txt");
	PASS();
	return 0;
}

int test_write_expands_file() {
	int fd = open("test5.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
	if (fd < 0)
		FAIL("open");

	write(fd, "ABC", 3);
	write(fd, "DEF", 3);
	write(fd, "GHI", 3);
	close(fd);

	fd = open("test5.txt", O_RDONLY);
	char buf[10] = {0};
	if (read(fd, buf, 9) != 9)
		FAIL("read expanded file");
	if (strcmp(buf, "ABCDEFGHI") != 0)
		FAIL("expanded file content");
	close(fd);

	unlink("test5.txt");
	PASS();
	return 0;
}

int test_lseek_seek_set() {
	int fd = open("test6.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
	if (fd < 0)
		FAIL("open");

	write(fd, "0123456789", 10);

	if (lseek(fd, 0, SEEK_SET) != 0)
		FAIL("lseek to start");
	char buf[3];
	read(fd, buf, 2);
	if (memcmp(buf, "01", 2) != 0)
		FAIL("read from start");

	if (lseek(fd, 5, SEEK_SET) != 5)
		FAIL("lseek to offset 5");
	read(fd, buf, 2);
	if (memcmp(buf, "56", 2) != 0)
		FAIL("read from offset 5");

	close(fd);
	unlink("test6.txt");
	PASS();
	return 0;
}

int test_lseek_seek_cur() {
	int fd = open("test7.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
	if (fd < 0)
		FAIL("open");

	write(fd, "0123456789", 10);
	lseek(fd, 0, SEEK_SET);

	read(fd, NULL, 3); // advance to position 3

	if (lseek(fd, 2, SEEK_CUR) != 5)
		FAIL("lseek forward from current");
	char buf[3];
	read(fd, buf, 2);
	if (memcmp(buf, "56", 2) != 0)
		FAIL("read after seek_cur forward");

	if (lseek(fd, -4, SEEK_CUR) != 3)
		FAIL("lseek backward from current");
	read(fd, buf, 2);
	if (memcmp(buf, "34", 2) != 0)
		FAIL("read after seek_cur backward");

	close(fd);
	unlink("test7.txt");
	PASS();
	return 0;
}

int test_lseek_seek_end() {
	int fd = open("test8.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
	if (fd < 0)
		FAIL("open");

	write(fd, "0123456789", 10);

	if (lseek(fd, 0, SEEK_END) != 10)
		FAIL("lseek to end");
	if (lseek(fd, -3, SEEK_END) != 7)
		FAIL("lseek from end");

	char buf[4];
	read(fd, buf, 3);
	if (memcmp(buf, "789", 3) != 0)
		FAIL("read from end offset");

	close(fd);
	unlink("test8.txt");
	PASS();
	return 0;
}

int test_lseek_beyond_eof() {
	int fd = open("test9.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
	if (fd < 0)
		FAIL("open");

	write(fd, "data", 4);

	if (lseek(fd, 10, SEEK_SET) != 10)
		FAIL("lseek beyond EOF");
	if (write(fd, "X", 1) != 1)
		FAIL("write after seek beyond EOF");

	close(fd);

	fd = open("test9.txt", O_RDONLY);
	char buf[12];
	ssize_t n = read(fd, buf, 11);
	if (n != 11)
		FAIL("read file with hole");
	if (memcmp(buf, "data", 4) != 0)
		FAIL("data before hole");
	// Check that bytes 4-9 are zeros (the hole)
	for (int i = 4; i < 10; i++) {
		if (buf[i] != 0)
			FAIL("hole not zero-filled");
	}
	if (buf[10] != 'X')
		FAIL("data after hole");

	close(fd);
	unlink("test9.txt");
	PASS();
	return 0;
}

int test_overwrite_data() {
	int fd = open("test10.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
	if (fd < 0)
		FAIL("open");

	write(fd, "AAAAAAAAAA", 10);
	lseek(fd, 3, SEEK_SET);
	write(fd, "BBBB", 4);

	close(fd);

	fd = open("test10.txt", O_RDONLY);
	char buf[11] = {0};
	read(fd, buf, 10);
	if (strcmp(buf, "AAABBBBAAA") != 0)
		FAIL("overwritten data mismatch");

	close(fd);
	unlink("test10.txt");
	PASS();
	return 0;
}

int test_append_mode() {
	int fd = open("test11.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
	if (fd < 0)
		FAIL("open");
	write(fd, "Initial", 7);
	close(fd);

	fd = open("test11.txt", O_WRONLY | O_APPEND);
	if (fd < 0)
		FAIL("open append");
	write(fd, " Data", 5);
	close(fd);

	fd = open("test11.txt", O_RDONLY);
	char buf[20] = {0};
	read(fd, buf, 12);
	if (strcmp(buf, "Initial Data") != 0)
		FAIL("append content");
	close(fd);

	unlink("test11.txt");
	PASS();
	return 0;
}

int test_append_ignores_lseek() {
	int fd = open("test12.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
	if (fd < 0)
		FAIL("open");
	write(fd, "12345", 5);
	close(fd);

	fd = open("test12.txt", O_WRONLY | O_APPEND);
	if (fd < 0)
		FAIL("open append");

	lseek(fd, 0, SEEK_SET); // Try to seek to beginning
	write(fd, "67890", 5);	// Should still append to end
	close(fd);

	fd = open("test12.txt", O_RDONLY);
	char buf[11] = {0};
	read(fd, buf, 10);
	if (strcmp(buf, "1234567890") != 0)
		FAIL("append should ignore lseek");
	close(fd);

	unlink("test12.txt");
	PASS();
	return 0;
}

int test_empty_file() {
	int fd = open("test13.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
	if (fd < 0)
		FAIL("open");
	close(fd);

	fd = open("test13.txt", O_RDONLY);
	char buf[10];
	ssize_t n = read(fd, buf, 10);
	if (n != 0)
		FAIL("read from empty file should return 0");
	close(fd);

	unlink("test13.txt");
	PASS();
	return 0;
}

int test_write_zero_bytes() {
	int fd = open("test14.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
	if (fd < 0)
		FAIL("open");

	ssize_t n = write(fd, "data", 0);
	if (n != 0)
		FAIL("write 0 bytes should return 0");

	close(fd);

	fd = open("test14.txt", O_RDONLY);
	char buf[10];
	n = read(fd, buf, 10);
	if (n != 0)
		FAIL("file should be empty after 0-byte write");
	close(fd);

	unlink("test14.txt");
	PASS();
	return 0;
}

int test_multiple_open_same_file() {
	int fd1 = open("test15.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
	if (fd1 < 0)
		FAIL("open 1");

	int fd2 = open("test15.txt", O_RDWR);
	if (fd2 < 0)
		FAIL("open 2");

	write(fd1, "AAA", 3);
	write(fd2, "BBB", 3);

	close(fd1);
	close(fd2);

	int fd = open("test15.txt", O_RDONLY);
	char buf[7] = {0};
	read(fd, buf, 6);

	if (strcmp(buf, "AAABBB") != 0 && strcmp(buf, "BBB") != 0) {
		FAIL("unexpected content with multiple fds");
	}
	close(fd);

	unlink("test15.txt");
	PASS();
	return 0;
}

int test_rdonly_write_fails() {
	int fd = open("test16.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
	if (fd < 0)
		FAIL("open create");
	write(fd, "data", 4);
	close(fd);

	fd = open("test16.txt", O_RDONLY);
	if (fd < 0)
		FAIL("open rdonly");

	ssize_t n = write(fd, "x", 1);
	if (n >= 0)
		FAIL("write to O_RDONLY should fail");

	close(fd);
	unlink("test16.txt");
	PASS();
	return 0;
}

int test_wronly_read_fails() {
	int fd = open("test17.txt", O_CREAT | O_WRONLY | O_TRUNC, 0644);
	if (fd < 0)
		FAIL("open wronly");

	char buf[10];
	ssize_t n = read(fd, buf, 10);
	if (n >= 0)
		FAIL("read from O_WRONLY should fail");

	close(fd);
	unlink("test17.txt");
	PASS();
	return 0;
}

int test_large_write_read() {
	int fd = open("test18.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
	if (fd < 0)
		FAIL("open");

	char wbuf[4096];
	for (int i = 0; i < 4096; i++) {
		wbuf[i] = (char)(i % 256);
	}

	if (write(fd, wbuf, 4096) != 4096)
		FAIL("large write");
	close(fd);

	fd = open("test18.txt", O_RDONLY);

	char rbuf[4096];

	if (read(fd, rbuf, 4096) != 4096)
		FAIL("large read");

	if (memcmp(wbuf, rbuf, 4096) != 0)
		FAIL("large data mismatch");
	close(fd);

	unlink("test18.txt");
	PASS();
	return 0;
}

int main(int argc, char *argv[]) {
	int failures = 0;

	// Basic operations

	test_basic_write_read();
	test_multiple_writes();
	test_partial_reads();
	test_read_past_eof();
	test_write_expands_file();

	// lseek tests
	test_lseek_seek_set();
	test_lseek_seek_cur();
	test_lseek_seek_end();
	test_lseek_beyond_eof();

	// Overwrite and append
	test_overwrite_data();
	test_append_mode();
	test_append_ignores_lseek();

	// Edge cases
	test_empty_file();
	test_write_zero_bytes();
	test_multiple_open_same_file();

	// Error conditions
	test_rdonly_write_fails();
	test_wronly_read_fails();

	// Large data
	test_large_write_read();

	printf("\n====================================\n");
	printf("%d/%d Tests Passed.\n", total_tests - failures, total_tests);
	printf("====================================\n");

	return failures > 0 ? 1 : 0;
}
