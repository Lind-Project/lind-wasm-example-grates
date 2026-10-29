// SPDX-License-Identifier: GPL-2.0
/*
 * tenant_grate.c — a benign tenant grate that sits ABOVE the attacker in the
 * chain and holds a secret in its memory. It forks the attacker and stays
 * alive so the attacker has an ancestor to try to steal from / hijack. The
 * monitor (one level up) denies both attempts.
 *
 * No 3i calls of its own — it is governed by inheritance but never forwards.
 *
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile char secret[] = "TENANT-A-SECRET-do-not-leak";

int main(int argc, char *argv[])
{
	pid_t pid, w;
	int status, rc = -1;

	if (argc < 2) {
		fprintf(stderr, "usage: %s ./atk_grate ./mon_cage\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	pid = fork();
	if (pid < 0) {
		perror("fork");
		exit(EXIT_FAILURE);
	}
	if (pid == 0) {
		execv(argv[1], &argv[1]);		/* ./atk_grate ./mon_cage */
		perror("execv atk_grate");
		_exit(EXIT_FAILURE);
	}

	fprintf(stderr, "[tenantA] %d holding secret @ %p, attacker=%d\n",
		(int)getpid(), (void *)secret, (int)pid);

	while ((w = wait(&status)) > 0)
		if (w == pid)
			rc = WIFEXITED(status) ? WEXITSTATUS(status) : -1;

	if (secret[0] == 'X')				/* keep `secret` resident */
		fprintf(stderr, "%s\n", (char *)secret);
	return rc == 0 ? 0 : 1;
}
