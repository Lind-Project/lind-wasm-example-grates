#include <dirent.h>
#include <errno.h>
#include <lind_syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "imfs.h"

// Dispatcher function
int pass_fptr_to_wt(uint64_t fn_ptr_uint, uint64_t cageid, uint64_t arg1,
		    uint64_t arg1cage, uint64_t arg2, uint64_t arg2cage,
		    uint64_t arg3, uint64_t arg3cage, uint64_t arg4,
		    uint64_t arg4cage, uint64_t arg5, uint64_t arg5cage,
		    uint64_t arg6, uint64_t arg6cage) {
	if (fn_ptr_uint == 0) {
		return -1;
	}

	int (*fn)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
		  uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
		  uint64_t) =
	    (int (*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
		     uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
		     uint64_t))(uintptr_t)fn_ptr_uint;

	return fn(cageid, arg1, arg1cage, arg2, arg2cage, arg3, arg3cage, arg4,
		  arg4cage, arg5, arg5cage, arg6, arg6cage);
}

// Stores list of files on host that need to be copied in before cage execution.
const char *preload_files;

// This is a util function to enable logging syscall invocations along with inputs and return value.
static inline void sys_log_args(const char *name, uint64_t arg1, uint64_t arg2,
				uint64_t arg3, uint64_t arg4, uint64_t arg5,
				uint64_t arg6, int ret) {
	char buf[512];
	size_t pos = 0;

	pos += snprintf(buf + pos, sizeof(buf) - pos, "%s (", name);

	uint64_t args[6] = {arg1, arg2, arg3, arg4, arg5, arg6};
	int first = 1;

	for (int i = 0; i < 6; i++) {
		if (args[i] == 0xdeadbeefdeadbeefULL)
			continue;

		if (!first)
			pos += snprintf(buf + pos, sizeof(buf) - pos, ", ");

		pos += snprintf(buf + pos, sizeof(buf) - pos, "%llu", args[i]);
		first = 0;
	}

	snprintf(buf + pos, sizeof(buf) - pos, ") = %d\n", ret);

	fprintf(stderr, "%s", buf);
}

#define SYS_LOG(name, ret)                                                     \
	sys_log_args((name), arg1, arg2, arg3, arg4, arg5, arg6, (ret))

/*
 * These functions are the wrappers for FS related syscalls.
 *
 * IMFS registers open, close, read, write, and fcntl syscalls.
*/

int open_grate(uint64_t cageid, uint64_t arg1, uint64_t arg1cage, uint64_t arg2,
	       uint64_t arg2cage, uint64_t arg3, uint64_t arg3cage,
	       uint64_t arg4, uint64_t arg4cage, uint64_t arg5,
	       uint64_t arg5cage, uint64_t arg6, uint64_t arg6cage) {
	int thiscage = getpid();

	// Copying the char* pathname into the grate's memory.
	char *pathname = malloc(256);

	if (pathname == NULL) {
		perror("malloc failed");
		exit(EXIT_FAILURE);
	}

	// This is an API provided by `lind_syscall.h` which is used to copy buffers
	// from one cage's memory to another's.
	//
	// This is useful for syscall wrappers where arguments passed by reference
	// must be copied into the grate before the operation and copied back to the cage
	// afterward.
	//
	// Syntax:
	//
	// copy_data_between_cages(
	// 	thiscage,	ID of the cage initiating the call.
	// 	srcaddr,	Virtual address in srccage where the data starts.
	// 	srccage,	Cage that owns the source data.
	// 	destaddr,	Destination virtual address in destcage.
	// 	destcage,	Cage that will receive the copied data.
	// 	len,		Number of bytes to copy for memcpy mode.
	// 	copytype,	Type of copy: 0 = raw (memcpy), 1 = bounded string (strncpy).
	// );
	copy_data_between_cages(thiscage, arg1cage, arg1, arg1cage,
				(uint64_t)pathname, thiscage, 256, 1);

	// Call imfs_open() from the IMFS library
	int ifd = imfs_open(cageid, pathname, arg2, arg3);

	SYS_LOG("OPEN", ifd);

	free(pathname);
	return ifd;
}

int fcntl_grate(uint64_t cageid, uint64_t arg1, uint64_t arg1cage,
		uint64_t arg2, uint64_t arg2cage, uint64_t arg3,
		uint64_t arg3cage, uint64_t arg4, uint64_t arg4cage,
		uint64_t arg5, uint64_t arg5cage, uint64_t arg6,
		uint64_t arg6cage) {
	int ret = imfs_fcntl(cageid, arg1, arg2, arg3);
	SYS_LOG("FCNTL", ret);
	return ret;
}

int unlink_grate(uint64_t cageid, uint64_t arg1, uint64_t arg1cage,
		uint64_t arg2, uint64_t arg2cage, uint64_t arg3,
		uint64_t arg3cage, uint64_t arg4, uint64_t arg4cage,
		uint64_t arg5, uint64_t arg5cage, uint64_t arg6,
		uint64_t arg6cage) {
	int thiscage = getpid();

	char *pathname = malloc(256);

	if (pathname == NULL) {
		perror("malloc failed");
		exit(EXIT_FAILURE);
	}

	copy_data_between_cages(thiscage, arg1cage, arg1, arg1cage,
				(uint64_t)pathname, thiscage, 256, 1);

	int ret = imfs_unlink(cageid, pathname);

	SYS_LOG("UNLINK", ret);
	return ret;
}

int close_grate(uint64_t cageid, uint64_t arg1, uint64_t arg1cage,
		uint64_t arg2, uint64_t arg2cage, uint64_t arg3,
		uint64_t arg3cage, uint64_t arg4, uint64_t arg4cage,
		uint64_t arg5, uint64_t arg5cage, uint64_t arg6,
		uint64_t arg6cage) {
	int ret = imfs_close(cageid, arg1);
	SYS_LOG("CLOSE", ret);
	return ret;
}

off_t lseek_grate(uint64_t cageid, uint64_t arg1, uint64_t arg1cage,
		  uint64_t arg2, uint64_t arg2cage, uint64_t arg3,
		  uint64_t arg3cage, uint64_t arg4, uint64_t arg4cage,
		  uint64_t arg5, uint64_t arg5cage, uint64_t arg6,
		  uint64_t arg6cage) {
	int thiscage = getpid();

	int fd = arg1;
	off_t offset = (off_t)arg2;
	int whence = (int)arg3;

	off_t ret = imfs_lseek(cageid, fd, offset, whence);

	SYS_LOG("LSEEK", ret);

	return ret;
}

// Read: Copy memory from grate to cage.
// Write: Copy memory from cage to grate.
int read_grate(uint64_t cageid, uint64_t arg1, uint64_t arg1cage, uint64_t arg2,
	       uint64_t arg2cage, uint64_t arg3, uint64_t arg3cage,
	       uint64_t arg4, uint64_t arg4cage, uint64_t arg5,
	       uint64_t arg5cage, uint64_t arg6, uint64_t arg6cage) {
	int thiscage = getpid();

	int fd = (int)arg1;
	int count = (size_t)arg3;

	ssize_t ret = 4321;

	char *buf = malloc(count);

	if (buf == NULL) {
		fprintf(stderr, "Malloc failed");
		exit(1);
	}

	ret = imfs_read(cageid, arg1, buf, count);
	// Sometimes read() is called with a NULL buffer, do not call cp_data in
	// that case.
	if (arg2 != 0) {
		copy_data_between_cages(
		    thiscage, arg2cage, (uint64_t)buf, thiscage, arg2, arg2cage,
		    count,
		    0 // Use copytype 0 so read exactly count
		      // bytes instead of stopping at '\0'
		);
	}

	SYS_LOG("READ", ret);

	free(buf);

	return ret;
}

int write_grate(uint64_t cageid, uint64_t arg1, uint64_t arg1cage,
		uint64_t arg2, uint64_t arg2cage, uint64_t arg3,
		uint64_t arg3cage, uint64_t arg4, uint64_t arg4cage,
		uint64_t arg5, uint64_t arg5cage, uint64_t arg6,
		uint64_t arg6cage) {
	int thiscage = getpid();
	int count = arg3;
	int ret = 1604;

	char *buffer = malloc(count);

	if (buffer == NULL) {
		perror("malloc failed.");
		exit(1);
	}

	copy_data_between_cages(thiscage, arg2cage, arg2, arg2cage,
				(uint64_t)buffer, thiscage, count, 0);

	if (arg1 < 3) {
		return write(arg1, buffer, count);
	}

	ret = imfs_write(cageid, arg1, buffer, count);
	free(buffer);

	SYS_LOG("WRITE", ret);

	return ret;
}

int main(int argc, char *argv[]) {
	// Should be at least two inputs (at least one grate file and one cage
	// file)
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <cage_file>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	int grateid = getpid();

	// Initialize imfs data structures.
	imfs_init();

	// Load files into memory before execution
	preload_files = getenv("PRELOADS");
	preloads(preload_files);

	pid_t pid = fork();
	if (pid < 0) {
		perror("fork failed");
		exit(EXIT_FAILURE);
	} else if (pid == 0) {
		int cageid = getpid();
		int ret;
		uint64_t fn_ptr_addr;

		// OPEN
		fn_ptr_addr = (uint64_t)(uintptr_t)&open_grate;
		ret = register_handler(cageid, 2, 1, grateid, fn_ptr_addr);

		// LSEEK
		fn_ptr_addr = (uint64_t)(uintptr_t)&lseek_grate;
		ret = register_handler(cageid, 8, 1, grateid, fn_ptr_addr);

		// READ
		fn_ptr_addr = (uint64_t)(uintptr_t)&read_grate;
		ret = register_handler(cageid, 0, 1, grateid, fn_ptr_addr);

		// WRITE
		fn_ptr_addr = (uint64_t)(uintptr_t)&write_grate;
		ret = register_handler(cageid, 1, 1, grateid, fn_ptr_addr);

		// CLOSE
		fn_ptr_addr = (uint64_t)(uintptr_t)&close_grate;
		ret = register_handler(cageid, 3, 1, grateid, fn_ptr_addr);

		// FCNTL
		fn_ptr_addr = (uint64_t)(uintptr_t)&fcntl_grate;
		ret = register_handler(cageid, 72, 1, grateid, fn_ptr_addr);

		// UNLINK
		fn_ptr_addr = (uint64_t)(uintptr_t)&unlink_grate;
		ret = register_handler(cageid, 87, 1, grateid, fn_ptr_addr);

		if (execv(argv[1], &argv[1]) == -1) {
			perror("execv failed");
			exit(EXIT_FAILURE);
		}
	}

	int status;
	int w;
	while (1) {
		w = wait(&status);
		if (w > 0) {
			printf("[Grate] terminated, status: %d\n", status);
			break;
		} else if (w < 0) {
			perror("[Grate] [Wait]");
		}
	}

	return 0;
}
