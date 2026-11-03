#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "threei.h"
#include "seccomp.h"

int main(int argc, char *argv[]) {
	if (argc < 3) {
		fprintf(stderr,
			"Usage: %s <seccomp-config.conf> <cage_binary> [args...]\n",
			argv[0]);
		exit(EXIT_FAILURE);
	}

	// parse the config file provided via the first command-line argument
	parse_config(argv[1]);

	int grateid = getpid();
	pid_t cageid = fork();

	if (cageid < 0) {
		perror("fork failed");
		exit(EXIT_FAILURE);
	}

	if (cageid == 0) {
		unsigned long fn = (unsigned long)(uintptr_t)&blacklist_handler;

		for (int i = 0; i < MAX_SYSCALLS; i++) {
			if (syscall_mode[i] == BL)
				register_handler(getpid(), (unsigned int)i,
						  grateid, fn);
		}

		if (execv(argv[2], &argv[2]) == -1) {
			perror("execv failed");
			_exit(EXIT_FAILURE);
		}
	}

	// Grate: wait for the cage; its blacklisted syscalls are denied
	// asynchronously by the 3i runtime threads.
	int status, w;
	while ((w = wait(&status)) < 0 && errno == EINTR)
		;

	return WIFEXITED(status) ? WEXITSTATUS(status) : EXIT_FAILURE;
}
