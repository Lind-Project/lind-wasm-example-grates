#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

static void die(const char *what) {
	perror(what);
	exit(1);
}

int main(void) {
	const char *base = "/tmp/exerciser";
	const char *subdir = "/tmp/exerciser/subdir";
	const char *file = "/tmp/exerciser/subdir/data.txt";

	unlink(file);
	rmdir(subdir);
	rmdir(base);

	if (mkdir(base, 0755) < 0 && errno != EEXIST)
		die("mkdir base");
	if (mkdir(subdir, 0755) < 0 && errno != EEXIST)
		die("mkdir subdir");

	int fd = open(file, O_CREAT | O_TRUNC | O_RDWR, 0644);
	if (fd < 0)
		die("open");

	if (write(fd, "alpha\n", 6) < 0)
		die("write");

	if (lseek(fd, 0, SEEK_SET) < 0)
		die("lseek after write");

	char read_buf[128];
	ssize_t n = read(fd, read_buf, sizeof(read_buf) - 1);
	if (n < 0)
		die("read");
	read_buf[n] = '\0';
	printf("read: %s", read_buf);

	int dupfd = dup(fd);
	if (dupfd < 0)
		die("dup");
	if (write(dupfd, "beta\n", 5) < 0)
		die("write dup");

	int dup2fd = dup2(fd, 20);
	if (dup2fd < 0)
		die("dup2");
	if (write(dup2fd, "gamma\n", 6) < 0)
		die("write dup2");

#ifdef _GNU_SOURCE
	int dup3fd = dup3(fd, 21, O_CLOEXEC);
	if (dup3fd < 0)
		die("dup3");
	if (write(dup3fd, "delta\n", 6) < 0)
		die("write dup3");
#endif
	struct iovec wiov[2];
	wiov[0].iov_base = "vec-";
	wiov[0].iov_len = 4;
	wiov[1].iov_base = "write\n";
	wiov[1].iov_len = 6;
	if (writev(fd, wiov, 2) < 0)
		die("writev");

	struct iovec pwiov[2];
	pwiov[0].iov_base = "PWRITE";
	pwiov[0].iov_len = 6;
	pwiov[1].iov_base = "V\n";
	pwiov[1].iov_len = 2;
	if (pwritev(fd, pwiov, 2, 0) < 0)
		die("pwritev");

	if (lseek(fd, 0, SEEK_SET) < 0)
		die("lseek before readv");

	char a[8] = {0};
	char b[16] = {0};
	struct iovec riov[2];
	riov[0].iov_base = a;
	riov[0].iov_len = sizeof(a) - 1;
	riov[1].iov_base = b;
	riov[1].iov_len = sizeof(b) - 1;
	n = readv(fd, riov, 2);
	if (n < 0)
		die("readv");
	printf("readv: %s%s", a, b);

	char pa[8] = {0};
	char pb[8] = {0};
	struct iovec priov[2];
	priov[0].iov_base = pa;
	priov[0].iov_len = sizeof(pa) - 1;
	priov[1].iov_base = pb;
	priov[1].iov_len = sizeof(pb) - 1;
	n = preadv(fd, priov, 2, 0);
	if (n < 0)
		die("preadv");
	printf("preadv: %s%s", pa, pb);

#ifdef _GNU_SOURCE
	if (close(dup3fd) < 0)
		die("close dup3");
#endif
	if (close(dup2fd) < 0)
		die("close dup2");
	if (close(dupfd) < 0)
		die("close dup");
	if (close(fd) < 0)
		die("close");

	puts("exerciser complete");
	return 0;
}
