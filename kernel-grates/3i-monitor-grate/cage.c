/*
 * cage.c — the victim at the bottom of the chain. It just opens a file;
 * the attacker grate interposes and redirects the path (the monitor allows
 * that forward, since path injection is whitelisted). Plain static program.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(void)
{
	char line[160];
	long fd;

	errno = 0;
	fd = syscall(__NR_open, "/tmp/mon_real.dat", O_CREAT | O_RDWR | O_TRUNC, 0644);
	snprintf(line, sizeof(line), "[cage] open -> %ld (errno=%d)\n",
		 fd, fd < 0 ? errno : 0);
	syscall(__NR_write, 2, line, strlen(line));
	if (fd >= 0)
		syscall(__NR_close, fd);
	return 0;
}
