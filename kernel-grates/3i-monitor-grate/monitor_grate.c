/*
 * monitor_grate.c — a single-chokepoint reference monitor. It interposes ONLY
 * make_threei_call, yet governs the whole 3i surface, because every 3i
 * operation a governed grate performs is issued THROUGH make_threei_call (the
 * uniform-entry convention, like lind-glibc's uniform 64-bit calling
 * convention). One handler therefore sees, and rules on:
 *
 *   inner_nr == register_handler       -> may `grate` interpose `target`?
 *   inner_nr == copy_data_between_cages -> may `caller` touch src and dst?
 *   inner_nr == anything else (a real syscall forward) -> default-deny nr set,
 *                no third-cage smuggling, per-(nr,arg) injection whitelist.
 *
 * The authority model is SUBTREE-SCOPED: a grate may register-handlers-on /
 * copy-data-from only pids inside its own subtree (itself + descendants). It
 * may not reach UP to an ancestor or SIDEWAYS to another tenant. Lineage comes
 * from the real process tree via /proc, so it is authoritative.
 *
 * Chain:  ./mon_grate ./tenantA_grate ./atk_grate ./mon_cage
 *           monitor      tenant A        attacker     victim
 * The attacker (a descendant grate) tries to steal tenant A's memory and hijack
 * tenant A's syscalls; the monitor denies both. It also governs the attacker's
 * forwards (path injection allowed, buffer injection would be denied).
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

#ifndef THREEI_ALLOW
#define THREEI_ALLOW (-4096L)
#endif

#define LOG(...) fprintf(stderr, __VA_ARGS__)

/* ---- lineage: authoritative subtree test via the real /proc tree ---- */
static pid_t read_ppid(pid_t pid)
{
	char path[64], buf[512], *rp;
	int fd, n;
	pid_t ppid = 0;

	snprintf(path, sizeof(path), "/proc/%d/stat", (int)pid);
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return 0;
	n = (int)read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return 0;
	buf[n] = '\0';
	rp = strrchr(buf, ')');			/* comm may contain spaces/parens */
	if (!rp || sscanf(rp + 1, " %*c %d", &ppid) != 1)
		return 0;
	return ppid;
}

static int is_descendant(pid_t t, pid_t anc)
{
	pid_t cur = t;
	int depth = 0;

	while (cur > 1 && depth++ < 40) {
		if (cur == anc)
			return 1;
		cur = read_ppid(cur);
	}
	return cur == anc;
}

/* a grate may reach only itself and its descendants */
static int may_reach(pid_t grate, pid_t target)
{
	return target == grate || is_descendant(target, grate);
}

/* ---- policy tables ---- */
static int nr_interpose_allowed(unsigned int nr)
{
	static const unsigned int ok[] = {
		__NR_open, __NR_openat, __NR_read, __NR_write,
		__NR_close, __NR_lseek, __NR_fstat, __NR_newfstatat,
	};
	size_t i;

	for (i = 0; i < sizeof(ok) / sizeof(ok[0]); i++)
		if (nr == ok[i])
			return 1;
	return 0;
}
static int nr_forward_allowed(unsigned int nr) { return nr_interpose_allowed(nr); }
static int injection_allowed(unsigned int nr, int argi)
{
	if (nr == __NR_open   && argi == 0) return 1;
	if (nr == __NR_openat && argi == 1) return 1;
	return 0;
}

/* read a 6-slot vector the caller passed by pointer into the monitor */
static int fetch6(pid_t caller, unsigned long uptr, void *dst, size_t sz)
{
	if (!uptr)
		return 0;			/* NULL vector: treat as all-zero */
	return copy_data_between_cages(caller, uptr, getpid(), (unsigned long)dst,
				       sz, THREEI_COPY_MEMCPY) == 0 ? 0 : -1;
}

/* the one handler: interposes make_threei_call, dispatches on inner_nr */
static long h_monitor(pid_t caller, const int ac[6], unsigned long a[6])
{
	unsigned int inner_nr = (unsigned int)a[0];
	pid_t primary = (pid_t)a[1];
	unsigned long u_argcage = a[2], u_args = a[3];
	unsigned long args[6] = { 0 };
	int argcage[6] = { 0 };
	int i;

	(void)ac;

	if (fetch6(caller, u_args, args, sizeof(args)) < 0) {
		LOG("[mon] DENY: caller=%d unreadable args; fail closed\n", caller);
		return -EPERM;
	}

	/* ---- control plane: register_handler ---- */
	if (inner_nr == __NR_register_handler) {
		pid_t target = (pid_t)args[0];
		unsigned int nr = (unsigned int)args[1];
		pid_t grate = (pid_t)args[2];

		if (!nr_interpose_allowed(nr)) {
			LOG("[mon] DENY register_handler: grate=%d may not interpose nr=%u\n",
			    grate, nr);
			return -EPERM;
		}
		if (!may_reach(grate, target)) {
			LOG("[mon] DENY register_handler: grate=%d target=%d OUTSIDE its subtree\n",
			    grate, target);
			return -EPERM;
		}
		LOG("[mon] ALLOW register_handler: grate=%d nr=%u target=%d\n",
		    grate, nr, target);
		return THREEI_ALLOW;
	}

	/* ---- control plane: copy_data_between_cages ---- */
	if (inner_nr == __NR_copy_data_between_cages) {
		pid_t src = (pid_t)args[0], dst = (pid_t)args[2];

		if (!may_reach(caller, src) || !may_reach(caller, dst)) {
			LOG("[mon] DENY copy_data: caller=%d src=%d dst=%d OUTSIDE its subtree\n",
			    caller, src, dst);
			return -EPERM;
		}
		LOG("[mon] ALLOW copy_data: caller=%d src=%d dst=%d\n", caller, src, dst);
		return THREEI_ALLOW;
	}

	/* ---- forwarding a nested make_threei_call: refuse ---- */
	if (inner_nr == __NR_make_threei_call) {
		LOG("[mon] DENY: caller=%d nested make_threei_call\n", caller);
		return -EPERM;
	}

	/* ---- a real syscall forward: default-deny nr + injection provenance ---- */
	if (!nr_forward_allowed(inner_nr)) {
		LOG("[mon] DENY forward: caller=%d nr=%u not in allowed set\n", caller, inner_nr);
		return -EPERM;
	}
	if (fetch6(caller, u_argcage, argcage, sizeof(argcage)) < 0) {
		LOG("[mon] DENY: caller=%d unreadable arg_cage; fail closed\n", caller);
		return -EPERM;
	}
	for (i = 0; i < 6; i++) {
		int owner = argcage[i];

		if (owner <= 0 || owner == (int)primary)
			continue;
		if (owner != (int)caller) {
			LOG("[mon] DENY forward: nr=%u arg%d from THIRD cage %d\n", inner_nr, i, owner);
			return -EPERM;
		}
		if (!injection_allowed(inner_nr, i)) {
			LOG("[mon] DENY forward: caller=%d may not inject arg%d of nr=%u\n",
			    caller, i, inner_nr);
			return -EPERM;
		}
	}
	LOG("[mon] ALLOW forward: caller=%d nr=%u primary=%d\n", caller, inner_nr, primary);
	return THREEI_ALLOW;
}

int main(int argc, char *argv[])
{
	pid_t monid = getpid(), pid, w;
	int status, rc = -1;

	if (argc < 3) {
		LOG("usage: %s ./tenantA_grate ./atk_grate ./mon_cage\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	pid = fork();
	if (pid < 0) {
		perror("fork");
		exit(EXIT_FAILURE);
	}
	if (pid == 0) {
		/* arm the one interposition; the whole subtree inherits it */
		if (register_handler(getpid(), __NR_make_threei_call, monid,
				     (unsigned long)h_monitor) < 0) {
			LOG("[mon] arm make_threei_call failed: %s\n", strerror(errno));
			_exit(EXIT_FAILURE);
		}
		LOG("[mon] monitor armed on make_threei_call -> %d; subtree governed\n", monid);
		execv(argv[1], &argv[1]);
		perror("execv tenantA_grate");
		_exit(EXIT_FAILURE);
	}

	LOG("[mon] %d governing the whole chain via one syscall (make_threei_call)\n", monid);
	while ((w = wait(&status)) > 0) {
		int c = WIFEXITED(status) ? WEXITSTATUS(status) : -1;

		LOG("[mon] pid %d exited, status %d\n", w, c);
		if (w == pid)
			rc = c;
	}
	LOG("[mon] ===== chain exit: %d =====\n", rc);
	return rc == 0 ? 0 : 1;
}
