/*
 * atk_grate.c — a malicious grate under the monitor.
 * The monitor (interposing only make_threei_call) therefore sees and vetoes
 * every control-plane op transparently. The attacker reaches OUTSIDE its own
 * subtree, up to its parent tenant, and is denied:
 *
 *   copy_data_between_cages(src = tenant)   -> DENY  (steal ancestor memory)
 *   register_handler(target = tenant)       -> DENY  (hijack ancestor syscalls)
 *   register_handler(target = own cage)      -> ALLOW (legit, in subtree)
 *   copy_data_between_cages(src = own cage)  -> ALLOW (legit fetch, in h_open)
 *
 * It then forwards the cage's open with an injected path; the monitor governs
 * that forward too (path injection whitelisted -> ALLOW).
 *
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include "threei.h"

#define LOG(...) fprintf(stderr, __VA_ARGS__)

static char decoy[] = "/tmp/mon_decoy.dat";

static long h_open(pid_t cage, const int ac[6], unsigned long a[6])
{
	static volatile int once;
	unsigned long na[6];
	int nac[6];

	(void)ac;
	if (!once) {
		char buf[64];
		long rc;

		once = 1;
		/* ordinary copy_data — in-subtree (cage), so the monitor ALLOWs */
		rc = copy_data_between_cages(cage, a[0], getpid(),
					     (unsigned long)buf, sizeof(buf),
					     THREEI_COPY_STRNCPY);
		LOG("[atk] copy cage->self (in-subtree): rc=%ld path=\"%s\"\n",
		    rc, rc >= 0 ? buf : "?");
	}

	/* inject path and forward; the monitor governs this forward too */
	memcpy(na, a, sizeof(na));
	memset(nac, 0, sizeof(nac));
	na[0] = (unsigned long)decoy;
	nac[0] = getpid();
	return make_threei_call(__NR_open, cage, nac, na);
}

int main(int argc, char *argv[])
{
	pid_t atkid = getpid(), tenantA = getppid(), pid, w;
	int status, rc = -1;
	char dummy[16];
	long r;

	if (argc < 2) {
		LOG("usage: %s ./mon_cage\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	pid = fork();
	if (pid < 0) {
		perror("fork");
		exit(EXIT_FAILURE);
	}
	if (pid == 0) {
		/* ordinary register_handler — in-subtree (own cage), so the monitor ALLOWs it */
		if (register_handler(getpid(), __NR_open, atkid,
				     (unsigned long)h_open) < 0)
			LOG("[atk] setup register open on cage: refused\n");
		execv(argv[1], &argv[1]);
		perror("execv cage");
		_exit(EXIT_FAILURE);
	}

	LOG("[atk] %d probing (tenantA=%d, cage=%d) with ordinary 3i calls\n",
	    atkid, tenantA, pid);

	/* reach UP to the ancestor — the monitor denies both (rc = -EPERM) */
	r = copy_data_between_cages(tenantA, 0x1000, atkid, (unsigned long)dummy,
				    sizeof(dummy), THREEI_COPY_MEMCPY);
	LOG("[atk] STEAL tenantA memory: rc=%ld (expect DENY = -%d)\n", r, EPERM);

	r = register_handler(tenantA, __NR_open, atkid, (unsigned long)h_open);
	LOG("[atk] HIJACK tenantA open: rc=%ld (expect DENY = -%d)\n", r, EPERM);

	while ((w = wait(&status)) > 0) {
		int c = WIFEXITED(status) ? WEXITSTATUS(status) : -1;

		if (w == pid)
			rc = c;
	}
	return rc == 0 ? 0 : 1;
}
