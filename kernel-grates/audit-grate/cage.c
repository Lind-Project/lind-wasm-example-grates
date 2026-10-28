#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

int main(void)
{
	const char *path = "testfile.txt";
	char buf[128];
	int fd, n;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "[cage] open(%s) failed: %s\n",
			path, strerror(errno));
		return 1;
	}
	printf("[cage] opened %s as fd %d\n", path, fd);

	n = read(fd, buf, sizeof(buf) - 1);
	if (n < 0) {
		fprintf(stderr, "[cage] read failed: %s\n", strerror(errno));
		close(fd);
		return 1;
	}
	buf[n] = '\0';
	printf("[cage] read %d bytes: %.*s\n", n, n, buf);

	close(fd);
	printf("[cage] done\n");
	return 0;
}
