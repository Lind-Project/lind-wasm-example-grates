#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <threei.h>

#define LOG(...) fprintf(stderr, "[inner-grate] " __VA_ARGS__)

/* openat handler — same shape as the standalone openat grate */
long open_grate(pid_t cageid, const int arg_cage[6],
                unsigned long args[6])
{
    int fwd_argcage[6];
    unsigned long fwd_args[6];
    static char blocked_path[] = "/etc/passwd";
    char original_path[4096] = {0};

    memcpy(fwd_argcage, arg_cage, sizeof(fwd_argcage));
    memcpy(fwd_args, args, sizeof(fwd_args));

    /* Read the original pathname from the cage. */
    if (copy_data_between_cages(cageid, args[1], getpid(),
                                (unsigned long)original_path,
                                sizeof(original_path) - 1, 0) < 0)
        return -EFAULT;

    original_path[sizeof(original_path) - 1] = '\0';

    /* Substitute only the intended test request. */
    if (strcmp(original_path, "testfile.txt") == 0) {
        fwd_args[1] = (unsigned long)blocked_path;
        fwd_argcage[1] = getpid();
    }

    return make_threei_call(__NR_openat, cageid,
                            fwd_argcage, fwd_args);
}

int main(int argc, char *argv[])
{
	if (argc < 2) { LOG("usage: %s <program> [args...]\n", argv[0]); exit(1); }

	pid_t grateid = getpid();
	pid_t pid = fork();
	if (pid < 0) { perror("fork"); exit(1); }

	if (pid == 0) {
		pid_t cageid = getpid();

		if (register_handler(cageid, __NR_openat, grateid,
				    (unsigned long)&open_grate) < 0) {
			fprintf(stderr,
				"[inner-grate] register openat DENIED by meta-grate: %s\n",
				strerror(errno));
			_exit(2);
		}
		LOG("openat registration ALLOWED by meta-grate; cage %d armed\n",
		   cageid);

		execv(argv[1], &argv[1]);
		perror("execv");
		_exit(1);
	}

	LOG("%d entering receive loop\n", grateid);

	int status;
	while (wait(&status) > 0) {
		if (WIFEXITED(status))
			LOG("cage exited with status %d\n", WEXITSTATUS(status));
		else if (WIFSIGNALED(status))
			LOG("cage killed by signal %d\n", WTERMSIG(status));
		else
			LOG("cage exited with unknown status\n");
	}
	return 0;
}
