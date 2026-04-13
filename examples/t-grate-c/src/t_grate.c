#include <assert.h>
#include <errno.h>
#include <lind_syscall.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define SYS_READ 0
#define SYS_CLONE 56
#define SYS_FORK 57
#define SYS_EXEC 59
#define SYS_EXIT 60
#define SYS_EXIT_GROUP 231
#define SYS_REGISTER_HANDLER 1001

#define INITIAL_CAPACITY 8

typedef int (*grate_handler_t)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
			       uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
			       uint64_t, uint64_t, uint64_t);

typedef struct {
	char **items;
	size_t len;
} StringList;

typedef struct {
	StringList primary;
	StringList secondary;
	StringList target;
} Parsed;

typedef struct {
	uint64_t target;
	uint64_t syscall_nr;
	uint64_t grate_id;
	uint64_t fn_ptr;
} InterpositionEntry;

typedef struct {
	uint64_t cage_id;
	uint64_t syscall_nr;
	uint64_t primary_alt;
	uint64_t secondary_alt;
	int has_primary_alt;
	int has_secondary_alt;
} TeeRouteEntry;

typedef struct {
	InterpositionEntry *entries;
	size_t len;
	size_t cap;
} InterpositionMap;

typedef struct {
	TeeRouteEntry *entries;
	size_t len;
	size_t cap;
} TeeRouteMap;

typedef struct {
	InterpositionMap interposition_map;
	uint64_t target_cage_id;
	uint64_t tee_cage_id;

	int has_primary_target;
	uint64_t primary_target_cage;

	int has_secondary_target;
	uint64_t secondary_target_cage;

	TeeRouteMap tee_route;

	int exiting;

	uint64_t next_alt;
} TeeState;

static TeeState g_tee;
static int g_tee_initialized = 0;
static pthread_mutex_t g_tee_lock = PTHREAD_MUTEX_INITIALIZER;

static void *xrealloc(void *ptr, size_t bytes) {
	void *next = realloc(ptr, bytes);
	if (next == NULL) {
		perror("realloc failed");
		exit(EXIT_FAILURE);
	}
	return next;
}

static char *xstrdup(const char *s) {
	char *out = strdup(s);
	if (out == NULL) {
		perror("strdup failed");
		exit(EXIT_FAILURE);
	}
	return out;
}

static void interposition_push(uint64_t target, uint64_t syscall_nr,
			       uint64_t grate_id, uint64_t fn_ptr) {
	if (g_tee.interposition_map.len == g_tee.interposition_map.cap) {
		size_t next_cap = g_tee.interposition_map.cap == 0
				      ? INITIAL_CAPACITY
				      : g_tee.interposition_map.cap * 2;
		g_tee.interposition_map.entries = xrealloc(
		    g_tee.interposition_map.entries,
		    next_cap * sizeof(g_tee.interposition_map.entries[0]));
		g_tee.interposition_map.cap = next_cap;
	}

	g_tee.interposition_map.entries[g_tee.interposition_map.len++] =
	    (InterpositionEntry){target, syscall_nr, grate_id, fn_ptr};
}

static TeeRouteEntry *tee_route_find(uint64_t cage_id, uint64_t syscall_nr) {
	size_t i;
	for (i = 0; i < g_tee.tee_route.len; i++) {
		TeeRouteEntry *entry = &g_tee.tee_route.entries[i];
		if (entry->cage_id == cage_id &&
		    entry->syscall_nr == syscall_nr) {
			return entry;
		}
	}
	return NULL;
}

static TeeRouteEntry *tee_route_get_or_insert(uint64_t cage_id,
					      uint64_t syscall_nr) {
	TeeRouteEntry *existing = tee_route_find(cage_id, syscall_nr);
	if (existing != NULL) {
		return existing;
	}

	if (g_tee.tee_route.len == g_tee.tee_route.cap) {
		size_t next_cap = g_tee.tee_route.cap == 0
				      ? INITIAL_CAPACITY
				      : g_tee.tee_route.cap * 2;
		g_tee.tee_route.entries =
		    xrealloc(g_tee.tee_route.entries,
			     next_cap * sizeof(g_tee.tee_route.entries[0]));
		g_tee.tee_route.cap = next_cap;
	}

	TeeRouteEntry *entry = &g_tee.tee_route.entries[g_tee.tee_route.len++];
	memset(entry, 0, sizeof(*entry));
	entry->cage_id = cage_id;
	entry->syscall_nr = syscall_nr;
	return entry;
}

static void tee_state_init(uint64_t tee_cage_id) {
	pthread_mutex_lock(&g_tee_lock);

	memset(&g_tee, 0, sizeof(g_tee));
	g_tee.tee_cage_id = tee_cage_id;
	g_tee.next_alt = 3000;
	g_tee_initialized = 1;

	pthread_mutex_unlock(&g_tee_lock);
}

static void tee_set_target_cage_id(uint64_t target_cage_id) {
	pthread_mutex_lock(&g_tee_lock);
	g_tee.target_cage_id = target_cage_id;
	pthread_mutex_unlock(&g_tee_lock);
}

static uint64_t tee_get_tee_cage_id(void) {
	uint64_t out;

	pthread_mutex_lock(&g_tee_lock);
	out = g_tee.tee_cage_id;
	pthread_mutex_unlock(&g_tee_lock);

	return out;
}

static int tee_is_exiting(void) {
	int exiting;

	pthread_mutex_lock(&g_tee_lock);
	exiting = g_tee.exiting;
	pthread_mutex_unlock(&g_tee_lock);

	return exiting;
}

static void tee_mark_exiting(void) {
	pthread_mutex_lock(&g_tee_lock);
	g_tee.exiting = 1;
	pthread_mutex_unlock(&g_tee_lock);
}

static int tee_has_primary_target(void) {
	int ready;

	pthread_mutex_lock(&g_tee_lock);
	ready = g_tee.has_primary_target;
	pthread_mutex_unlock(&g_tee_lock);

	return ready;
}

static int tee_has_both_targets(void) {
	int ready;

	pthread_mutex_lock(&g_tee_lock);
	ready = g_tee.has_primary_target && g_tee.has_secondary_target;
	pthread_mutex_unlock(&g_tee_lock);

	return ready;
}

static void tee_set_target_from_exec(uint64_t exec_cage) {
	pthread_mutex_lock(&g_tee_lock);

	if (g_tee.has_primary_target) {
		g_tee.has_secondary_target = 1;
		g_tee.secondary_target_cage = exec_cage;
	} else {
		g_tee.has_primary_target = 1;
		g_tee.primary_target_cage = exec_cage;
	}

	pthread_mutex_unlock(&g_tee_lock);
}

static int is_primary_only_syscall(uint64_t syscall_number) {
	return syscall_number == SYS_FORK || syscall_number == SYS_CLONE ||
	       syscall_number == SYS_EXEC || syscall_number == SYS_EXIT;
}

static char **to_exec_argv(const StringList *list) {
	size_t i;
	char **argv = calloc(list->len + 1, sizeof(char *));
	if (argv == NULL) {
		perror("calloc failed");
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < list->len; i++) {
		argv[i] = list->items[i];
	}
	argv[list->len] = NULL;

	return argv;
}

static void print_string_list(const char *name, const StringList *list) {
	size_t i;
	printf("%s=[", name);
	for (i = 0; i < list->len; i++) {
		printf("\"%s\"", list->items[i]);
		if (i + 1 < list->len) {
			printf(", ");
		}
	}
	printf("]");
}

static void print_parsed(const Parsed *parsed) {
	printf("[t-grate] Parsed= ");
	print_string_list("primary", &parsed->primary);
	printf(" ");
	print_string_list("secondary", &parsed->secondary);
	printf(" ");
	print_string_list("target", &parsed->target);
	printf("\n");
}

static StringList parse_block(char **args, int argc, int *index) {
	StringList out = {0};

	if (*index >= argc || strcmp(args[*index], "%{") != 0) {
		fprintf(stderr, "expected %%{ at argv[%d]\n", *index);
		exit(EXIT_FAILURE);
	}
	*index += 1;

	while (*index < argc) {
		char *tok = args[*index];
		*index += 1;

		out.items = xrealloc(out.items, (out.len + 1) * sizeof(char *));
		out.items[out.len++] = xstrdup(tok);

		if (strcmp(tok, "%}") == 0) {
			return out;
		}
	}

	fprintf(stderr, "unterminated %%{ block\n");
	exit(EXIT_FAILURE);
}

static StringList parse_rest(char **args, int argc, int *index) {
	StringList out = {0};

	while (*index < argc) {
		out.items = xrealloc(out.items, (out.len + 1) * sizeof(char *));
		out.items[out.len++] = xstrdup(args[*index]);
		*index += 1;
	}

	if (out.len == 0) {
		fprintf(stderr, "missing target args\n");
		exit(EXIT_FAILURE);
	}

	return out;
}

static Parsed parse_args(char **args, int argc) {
	int idx = 0;
	Parsed parsed;

	parsed.primary = parse_block(args, argc, &idx);
	parsed.secondary = parse_block(args, argc, &idx);
	parsed.target = parse_rest(args, argc, &idx);

	return parsed;
}

static void free_string_list(StringList *list) {
	size_t i;
	for (i = 0; i < list->len; i++) {
		free(list->items[i]);
	}
	free(list->items);
	list->items = NULL;
	list->len = 0;
}

static void free_parsed(Parsed *parsed) {
	free_string_list(&parsed->primary);
	free_string_list(&parsed->secondary);
	free_string_list(&parsed->target);
}

int pass_fptr_to_wt(uint64_t fn_ptr_uint, uint64_t cageid, uint64_t arg1,
		    uint64_t arg1cage, uint64_t arg2, uint64_t arg2cage,
		    uint64_t arg3, uint64_t arg3cage, uint64_t arg4,
		    uint64_t arg4cage, uint64_t arg5, uint64_t arg5cage,
		    uint64_t arg6, uint64_t arg6cage) {
	if (fn_ptr_uint == 0) {
		fprintf(stderr, "[t-grate] Invalid function ptr\n");
		assert(0);
	}

	grate_handler_t fn = (grate_handler_t)(uintptr_t)fn_ptr_uint;
	return fn(cageid, arg1, arg1cage, arg2, arg2cage, arg3, arg3cage, arg4,
		  arg4cage, arg5, arg5cage, arg6, arg6cage);
}

static int do_syscall(uint64_t calling_cage, uint64_t nr,
		      const uint64_t args[6], const uint64_t arg_cages[6]) {
	uint64_t tee_cage = tee_get_tee_cage_id();

	return make_threei_call(nr, 0, tee_cage, calling_cage, args[0],
				arg_cages[0], args[1], arg_cages[1], args[2],
				arg_cages[2], args[3], arg_cages[3], args[4],
				arg_cages[4], args[5], arg_cages[5], 0);
}

static int read_handler(uint64_t _cageid, uint64_t arg1, uint64_t arg1cage,
			uint64_t arg2, uint64_t arg2cage, uint64_t arg3,
			uint64_t arg3cage, uint64_t arg4, uint64_t arg4cage,
			uint64_t arg5, uint64_t arg5cage, uint64_t arg6,
			uint64_t arg6cage);

static grate_handler_t get_tee_handler(uint64_t syscall_nr) {
	if (syscall_nr == SYS_READ) {
		return read_handler;
	}
	return NULL;
}

static int tee_dispatch(uint64_t syscall_number, uint64_t cage_id,
			const uint64_t args[6], const uint64_t arg_cages[6]) {
	uint64_t primary_syscall = syscall_number;
	uint64_t secondary_syscall = 0;
	int has_secondary = 0;

	pthread_mutex_lock(&g_tee_lock);
	TeeRouteEntry *route_entry = tee_route_find(arg_cages[0], SYS_READ);
	if (route_entry == NULL) {
		pthread_mutex_unlock(&g_tee_lock);
		fprintf(
		    stderr,
		    "[t-grate] missing tee_route for cage=%llu syscall=%d\n",
		    (unsigned long long)arg_cages[0], SYS_READ);
		return -1;
	}

	if (route_entry->has_primary_alt) {
		primary_syscall = route_entry->primary_alt;
	}
	if (route_entry->has_secondary_alt) {
		has_secondary = 1;
		secondary_syscall = route_entry->secondary_alt;
	}
	pthread_mutex_unlock(&g_tee_lock);

	int primary_result =
	    do_syscall(cage_id, primary_syscall, args, arg_cages);
	printf("[t-grate] syscall_number=%llu primary=%d\n",
	       (unsigned long long)syscall_number, primary_result);

	if (is_primary_only_syscall(syscall_number)) {
		return primary_result;
	}

	if (has_secondary) {
		int secondary_result =
		    do_syscall(cage_id, secondary_syscall, args, arg_cages);
		printf("[t-grate] syscall_number=%llu secondary=%d\n",
		       (unsigned long long)syscall_number, secondary_result);
	}

	return primary_result;
}

static int read_handler(uint64_t _cageid, uint64_t arg1, uint64_t arg1cage,
			uint64_t arg2, uint64_t arg2cage, uint64_t arg3,
			uint64_t arg3cage, uint64_t arg4, uint64_t arg4cage,
			uint64_t arg5, uint64_t arg5cage, uint64_t arg6,
			uint64_t arg6cage) {
	(void)_cageid;

	uint64_t args[6] = {arg1, arg2, arg3, arg4, arg5, arg6};
	uint64_t arg_cages[6] = {arg1cage, arg2cage, arg3cage,
				 arg4cage, arg5cage, arg6cage};

	return tee_dispatch(SYS_READ, arg1cage, args, arg_cages);
}

static int register_handler_handler(uint64_t _cageid, uint64_t target_cage,
				    uint64_t syscall_nr, uint64_t _arg2,
				    uint64_t grate_id, uint64_t handler_fn_ptr,
				    uint64_t _arg3cage, uint64_t _arg4,
				    uint64_t _arg4cage, uint64_t _arg5,
				    uint64_t _arg5cage, uint64_t _arg6,
				    uint64_t _arg6cage) {
	(void)_cageid;
	(void)_arg2;
	(void)_arg3cage;
	(void)_arg4;
	(void)_arg4cage;
	(void)_arg5;
	(void)_arg5cage;
	(void)_arg6;
	(void)_arg6cage;

	if (get_tee_handler(syscall_nr) != NULL) {
		pthread_mutex_lock(&g_tee_lock);
		interposition_push(target_cage, syscall_nr, grate_id,
				   handler_fn_ptr);
		pthread_mutex_unlock(&g_tee_lock);
	}

	{
		const uint64_t args[6] = {target_cage, 0, handler_fn_ptr,
					  0,	       0, 0};
		const uint64_t arg_cages[6] = {syscall_nr, grate_id, 0,
					       0,	   0,	     0};
		return do_syscall(grate_id, SYS_REGISTER_HANDLER, args,
				  arg_cages);
	}
}

static int exec_handler(uint64_t _cageid, uint64_t arg1, uint64_t arg1cage,
			uint64_t arg2, uint64_t arg2cage, uint64_t arg3,
			uint64_t arg3cage, uint64_t arg4, uint64_t arg4cage,
			uint64_t arg5, uint64_t arg5cage, uint64_t arg6,
			uint64_t arg6cage) {
	(void)_cageid;

	uint64_t tee_cage = tee_get_tee_cage_id();

	char buf[256];
	memset(buf, 0, sizeof(buf));
	if (copy_data_between_cages(tee_cage, arg1cage, arg1, arg1cage,
				    (uint64_t)buf, tee_cage, sizeof(buf),
				    0) != 0) {
		fprintf(stderr, "[tee-grate] Unable to read the execve path\n");
		assert(0);
	}

	if (strcmp(buf, "%}") == 0) {
		tee_set_target_from_exec(arg1cage);

		while (1) {
			sleep(10);

			if (tee_is_exiting()) {
				printf("[exec] cageid=%llu exiting=1\n",
				       (unsigned long long)arg1cage);
				return 0;
			}
		}
	}

	{
		const uint64_t args[6] = {arg1, arg2, arg3, arg4, arg5, arg6};
		const uint64_t arg_cages[6] = {arg1cage, arg2cage, arg3cage,
					       arg4cage, arg5cage, arg6cage};
		return do_syscall(arg1cage, SYS_EXEC, args, arg_cages);
	}
}

static int target_exit_handler(uint64_t _cageid, uint64_t arg1,
			       uint64_t arg1cage, uint64_t arg2,
			       uint64_t arg2cage, uint64_t arg3,
			       uint64_t arg3cage, uint64_t arg4,
			       uint64_t arg4cage, uint64_t arg5,
			       uint64_t arg5cage, uint64_t arg6,
			       uint64_t arg6cage) {
	(void)_cageid;

	uint64_t stack_targets[2] = {0, 0};

	pthread_mutex_lock(&g_tee_lock);
	stack_targets[0] = g_tee.primary_target_cage;
	stack_targets[1] = g_tee.secondary_target_cage;
	pthread_mutex_unlock(&g_tee_lock);

	printf(
	    "[t-grate | target-exit-handler] %llu %llu %llu %llu %llu %llu\n",
	    (unsigned long long)arg1, (unsigned long long)arg2,
	    (unsigned long long)arg3, (unsigned long long)arg4,
	    (unsigned long long)arg5, (unsigned long long)arg6);
	printf(
	    "[t-grate | target-exit-handler] %llu %llu %llu %llu %llu %llu\n",
	    (unsigned long long)arg1cage, (unsigned long long)arg2cage,
	    (unsigned long long)arg3cage, (unsigned long long)arg4cage,
	    (unsigned long long)arg5cage, (unsigned long long)arg6cage);
	printf("[t-grate | target-exit-handler] target_cage=%llu "
	       "primary_stack_target=%llu secondary_stack_target=%llu\n",
	       (unsigned long long)arg1cage,
	       (unsigned long long)stack_targets[0],
	       (unsigned long long)stack_targets[1]);

	const uint64_t args[6] = {arg1, arg2, arg3, arg4, arg5, arg6};
	const uint64_t arg_cages[6] = {arg1cage, arg2cage, arg3cage,
				       arg4cage, arg5cage, arg6cage};

	int return_value =
	    do_syscall(arg1cage, SYS_EXIT_GROUP, args, arg_cages);

	const uint64_t stack_exit_args[6] = {arg1, 1, arg3, arg4, arg5, arg6};
	do_syscall(stack_targets[0], SYS_EXIT_GROUP, stack_exit_args,
		   arg_cages);
	do_syscall(stack_targets[1], SYS_EXIT_GROUP, stack_exit_args,
		   arg_cages);

	tee_mark_exiting();
	return return_value;
}

static void register_lifecycle_handlers(uint64_t cage_id) {
	uint64_t tee_cage = tee_get_tee_cage_id();

	if (register_handler(cage_id, SYS_REGISTER_HANDLER, tee_cage,
			     (uint64_t)(uintptr_t)&register_handler_handler) !=
	    0) {
		fprintf(stderr,
			"[tee-grate] failed to register lifecycle handler %d "
			"on cage %llu\n",
			SYS_REGISTER_HANDLER, (unsigned long long)cage_id);
	}

	if (register_handler(cage_id, SYS_EXEC, tee_cage,
			     (uint64_t)(uintptr_t)&exec_handler) != 0) {
		fprintf(stderr,
			"[tee-grate] failed to register lifecycle handler %d "
			"on cage %llu\n",
			SYS_EXEC, (unsigned long long)cage_id);
	}
}

static void register_target_handlers(uint64_t cage_id) {
	printf("[r-t-h] Actual target=%llu\n", (unsigned long long)cage_id);

	uint64_t stack_targets[2] = {0, 0};
	size_t stack_count = 0;

	pthread_mutex_lock(&g_tee_lock);
	if (g_tee.has_primary_target) {
		stack_targets[stack_count++] = g_tee.primary_target_cage;
	}
	if (g_tee.has_secondary_target) {
		stack_targets[stack_count++] = g_tee.secondary_target_cage;
	}
	pthread_mutex_unlock(&g_tee_lock);

	if (stack_count < 2) {
		fprintf(stderr, "[r-t-h] expected two stack targets, got %zu\n",
			stack_count);
		return;
	}

	pthread_mutex_lock(&g_tee_lock);
	for (size_t i = 0; i < g_tee.interposition_map.len; i++) {
		InterpositionEntry *m = &g_tee.interposition_map.entries[i];
		uint64_t stack_target = m->target;
		uint64_t syscall_nr = m->syscall_nr;
		uint64_t grate_id = m->grate_id;
		uint64_t fn_ptr = m->fn_ptr;

		if (stack_target != stack_targets[0] &&
		    stack_target != stack_targets[1]) {
			continue;
		}

		uint64_t alt_nr = ++g_tee.next_alt;
		TeeRouteEntry *tee_route =
		    tee_route_get_or_insert(cage_id, syscall_nr);

		if (stack_target == stack_targets[0]) {
			tee_route->has_primary_alt = 1;
			tee_route->primary_alt = alt_nr;
		}
		if (stack_target == stack_targets[1]) {
			tee_route->has_secondary_alt = 1;
			tee_route->secondary_alt = alt_nr;
		}

		uint64_t tee_cage_id = g_tee.tee_cage_id;
		uint64_t target_cage_id = g_tee.target_cage_id;

		printf("[r-t-h] %llu %llu %llu %llu\n",
		       (unsigned long long)tee_cage_id,
		       (unsigned long long)alt_nr, (unsigned long long)grate_id,
		       (unsigned long long)fn_ptr);

		const uint64_t args[6] = {tee_cage_id, 0, fn_ptr, 0, 0, 0};
		const uint64_t arg_cages[6] = {alt_nr, grate_id, 0, 0, 0, 0};
		pthread_mutex_unlock(&g_tee_lock);

		do_syscall(tee_cage_id, SYS_REGISTER_HANDLER, args, arg_cages);
		printf("[r-t-h] Alt registration done.\n");

		grate_handler_t handler = get_tee_handler(syscall_nr);
		if (handler != NULL) {
			register_handler(target_cage_id, syscall_nr,
					 tee_cage_id,
					 (uint64_t)(uintptr_t)handler);
		} else {
			printf("[r-t-h] No handler for %llu\n",
			       (unsigned long long)syscall_nr);
		}

		pthread_mutex_lock(&g_tee_lock);
	}

	uint64_t tee_cage_id = g_tee.tee_cage_id;
	uint64_t target_cage_id = g_tee.target_cage_id;
	pthread_mutex_unlock(&g_tee_lock);

	if (register_handler(target_cage_id, SYS_EXIT, tee_cage_id,
			     (uint64_t)(uintptr_t)&target_exit_handler) == 0) {
		printf("[t-grate] exit registered %llu %d %llu\n",
		       (unsigned long long)target_cage_id, SYS_EXIT,
		       (unsigned long long)tee_cage_id);
	} else {
		printf("[t-grate] exit registration failed\n");
	}

	if (register_handler(target_cage_id, SYS_EXIT_GROUP, tee_cage_id,
			     (uint64_t)(uintptr_t)&target_exit_handler) == 0) {
		printf("[t-grate] exit_group registered %llu %d %llu\n",
		       (unsigned long long)target_cage_id, SYS_EXIT_GROUP,
		       (unsigned long long)tee_cage_id);
	} else {
		printf("[t-grate] exit_group registration failed\n");
	}
}

int main(int argc, char *argv[]) {
	if (argc < 2) {
		fprintf(stderr,
			"Usage: %s %%{ <primary...> %%} %%{ <secondary...> %%} "
			"<target...>\n",
			argv[0]);
		return EXIT_FAILURE;
	}

	Parsed parsed = parse_args(&argv[1], argc - 1);
	print_parsed(&parsed);

	tee_state_init((uint64_t)getpid());
	if (!g_tee_initialized) {
		fprintf(stderr, "[t-grate] tee state init failed\n");
		return EXIT_FAILURE;
	}

	pid_t stackone = fork();
	if (stackone < 0) {
		perror("fork failed");
		return EXIT_FAILURE;
	}

	if (stackone == 0) {
		uint64_t cage_id = (uint64_t)getpid();
		printf("[t-grate] primary_grateid=%llu ",
		       (unsigned long long)cage_id);
		print_string_list("primary", &parsed.primary);
		printf("\n");

		register_lifecycle_handlers(cage_id);

		char **exec_argv = to_exec_argv(&parsed.primary);
		int exec_ret = execv(exec_argv[0], exec_argv);
		printf("[primary] exec_ret... %d\n", exec_ret);
		free(exec_argv);
		exit(0);
	}

	while (!tee_has_primary_target()) {
	}

	pid_t stacktwo = fork();
	if (stacktwo < 0) {
		perror("fork failed");
		return EXIT_FAILURE;
	}

	if (stacktwo == 0) {
		uint64_t cage_id = (uint64_t)getpid();
		printf("[t-grate] secondary_grateid=%llu ",
		       (unsigned long long)cage_id);
		print_string_list("secondary", &parsed.secondary);
		printf("\n");

		register_lifecycle_handlers(cage_id);

		char **exec_argv = to_exec_argv(&parsed.secondary);
		int exec_ret = execv(exec_argv[0], exec_argv);
		printf("[secondary] exec_ret... %d\n", exec_ret);
		free(exec_argv);
		exit(0);
	}

	printf("[t-grate] waiting for primary and secondary stacks to be "
	       "initialized...\n");
	while (!tee_has_both_targets()) {
	}

	printf("[t-grate] 2 stacks initialized, running target cages...\n");
	print_parsed(&parsed);

	sem_t *sem = mmap(NULL, sizeof(*sem), PROT_READ | PROT_WRITE,
			  MAP_SHARED | MAP_ANON, -1, 0);
	if (sem == MAP_FAILED) {
		perror("[tee-grate] mmap failed");
		return EXIT_FAILURE;
	}

	if (sem_init(sem, 1, 0) < 0) {
		perror("[tee-grate] sem_init failed");
		return EXIT_FAILURE;
	}

	pid_t targetstack = fork();
	if (targetstack < 0) {
		perror("fork failed");
		return EXIT_FAILURE;
	}

	if (targetstack == 0) {
		uint64_t cage_id = (uint64_t)getpid();
		printf("[t-grate] target, ");
		print_parsed(&parsed);
		printf("[t-grate] target_stackid=%llu ",
		       (unsigned long long)cage_id);
		print_string_list("target_stack", &parsed.target);
		printf("\n");

		sem_wait(sem);

		char **exec_argv = to_exec_argv(&parsed.target);
		int exec_ret = execv(exec_argv[0], exec_argv);
		printf("[target] exec_ret... %d\n", exec_ret);
		free(exec_argv);
		exit(0);
	}

	tee_set_target_cage_id((uint64_t)targetstack);
	register_target_handlers((uint64_t)targetstack);

	sem_post(sem);

	while (1) {
		int status = 0;
		pid_t ret = waitpid(-1, &status, 0);
		if (ret <= 0) {
			break;
		}
		printf("[t-grate] child %d exited with status %d\n", (int)ret,
		       status);
	}

	sem_destroy(sem);
	munmap(sem, sizeof(*sem));

	printf("[t-grate] All children exited. Exiting.\n");

	free_parsed(&parsed);
	return 0;
}
