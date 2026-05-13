#define _GNU_SOURCE

/* imfs_test.c — Test binary for the Rust IMFS grate.
 *
 * This is a cage binary that exercises the IMFS through standard POSIX
 * syscalls. The IMFS grate intercepts these syscalls and handles them
 * in-memory.
 *
 * Expected invocation:
 *   lind-wasm imfs-grate-rs.cwasm imfs_test.cwasm
 *
 * Each test prints PASS/FAIL. Exit code 0 if all tests pass, 1 otherwise.
 */
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

static int tests_run = 0;
static int tests_passed = 0;

#define CHECK(desc, cond)                                                      \
	do {                                                                   \
		tests_run++;                                                   \
		if (cond) {                                                    \
			printf("  PASS: %s\n", desc);                          \
			tests_passed++;                                        \
		} else {                                                       \
			printf("  FAIL: %s (errno=%d)\n", desc, errno);        \
		}                                                              \
	} while (0)

/*  Test 1: Basic open/write/read/close cycle  */

static void test_basic_rw(void) {
	printf("\n[test_basic_rw]\n");

	const char *msg = "hello imfs";
	char buf[64] = {0};

	/* Create a new file and write to it. */
	int fd = open("/test_basic", O_CREAT | O_RDWR, 0644);
	CHECK("open /test_basic with O_CREAT", fd >= 0);
	if (fd < 0)
		return;

	ssize_t nw = write(fd, msg, strlen(msg));
	CHECK("write returns correct count", nw == (ssize_t)strlen(msg));

	/* Seek back to beginning and read. */
	off_t pos = lseek(fd, 0, SEEK_SET);
	CHECK("lseek to beginning returns 0", pos == 0);

	ssize_t nr = read(fd, buf, sizeof(buf) - 1);
	CHECK("read returns correct count", nr == (ssize_t)strlen(msg));
	CHECK("read data matches written data",
	      memcmp(buf, msg, strlen(msg)) == 0);

	int ret = close(fd);
	CHECK("close succeeds", ret == 0);

	fd = open("/test_basic", O_WRONLY | O_TRUNC);
	CHECK("open /test_basic with O_TRUNC", fd >= 0);
	if (fd >= 0) {
		struct stat st;
		CHECK("fstat after O_TRUNC", fstat(fd, &st) == 0);
		CHECK("O_TRUNC sets size to 0", st.st_size == 0);
		close(fd);
	}
}

/*  Test 2: Open nonexistent file without O_CREAT  */

static void test_open_nocreat(void) {
	printf("\n[test_open_nocreat]\n");

	int fd = open("/does_not_exist", O_RDONLY);
	CHECK("open nonexistent without O_CREAT fails", fd < 0);
}

/*  Test 3: O_APPEND writes at end  */

static void test_append(void) {
	printf("\n[test_append]\n");

	int fd = open("/test_append", O_CREAT | O_RDWR, 0644);
	CHECK("create /test_append", fd >= 0);
	if (fd < 0)
		return;

	write(fd, "aaa", 3);
	close(fd);

	/* Reopen with O_APPEND and write more. */
	fd = open("/test_append", O_WRONLY | O_APPEND);
	CHECK("reopen with O_APPEND", fd >= 0);
	if (fd < 0)
		return;

	write(fd, "bbb", 3);
	close(fd);

	/* Read back full contents. */
	fd = open("/test_append", O_RDONLY);
	CHECK("reopen for read", fd >= 0);
	if (fd < 0)
		return;

	char buf[64] = {0};
	ssize_t nr = read(fd, buf, sizeof(buf) - 1);
	CHECK("total size is 6", nr == 6);
	CHECK("data is aaabbb", memcmp(buf, "aaabbb", 6) == 0);

	close(fd);
}

/*  Test 4: lseek with SEEK_CUR and SEEK_END  */

static void test_lseek(void) {
	printf("\n[test_lseek]\n");

	int fd = open("/test_lseek", O_CREAT | O_RDWR, 0644);
	CHECK("create /test_lseek", fd >= 0);
	if (fd < 0)
		return;

	write(fd, "0123456789", 10);

	/* SEEK_SET to position 5. */
	off_t pos = lseek(fd, 5, SEEK_SET);
	CHECK("SEEK_SET to 5", pos == 5);

	/* SEEK_CUR +2 = 7. */
	pos = lseek(fd, 2, SEEK_CUR);
	CHECK("SEEK_CUR +2 = 7", pos == 7);

	/* SEEK_END -3 = 7. */
	pos = lseek(fd, -3, SEEK_END);
	CHECK("SEEK_END -3 = 7", pos == 7);

	pos = lseek(fd, -20, SEEK_SET);
	CHECK("negative SEEK_SET fails", pos == -1 && errno == EINVAL);

	/* Read from position 7: should get "789". */
	char buf[4] = {0};
	ssize_t nr = read(fd, buf, 3);
	CHECK("read 3 bytes from pos 7", nr == 3);
	CHECK("data is 789", memcmp(buf, "789", 3) == 0);

	close(fd);
}

/*  Test 5: pread and pwrite (positional, no offset change)  */

static void test_pread_pwrite(void) {
	printf("\n[test_pread_pwrite]\n");

	int fd = open("/test_preadwrite", O_CREAT | O_RDWR, 0644);
	CHECK("create /test_preadwrite", fd >= 0);
	if (fd < 0)
		return;

	write(fd, "AAAAAAAAAA", 10); /* 10 A's */

	/* pwrite "BB" at offset 3 — fd offset should NOT change. */
	ssize_t nw = pwrite(fd, "BB", 2, 3);
	CHECK("pwrite 2 bytes at offset 3", nw == 2);

	/* fd offset should still be 10 (from the initial write). */
	off_t pos = lseek(fd, 0, SEEK_CUR);
	CHECK("fd offset unchanged after pwrite", pos == 10);

	/* pread 4 bytes from offset 2. */
	char buf[5] = {0};
	ssize_t nr = pread(fd, buf, 4, 2);
	CHECK("pread 4 bytes from offset 2", nr == 4);
	CHECK("data is ABBA", memcmp(buf, "ABBA", 4) == 0);

	/* fd offset still unchanged. */
	pos = lseek(fd, 0, SEEK_CUR);
	CHECK("fd offset unchanged after pread", pos == 10);

	CHECK("pread negative offset fails", pread(fd, buf, 1, -1) == -1 && errno == EINVAL);
	CHECK("pwrite negative offset fails", pwrite(fd, "Z", 1, -1) == -1 && errno == EINVAL);

	close(fd);
}

/*  Test 6: mkdir and nested file creation  */

static void test_mkdir(void) {
	printf("\n[test_mkdir]\n");

	int ret = mkdir("/mydir", 0755);
	CHECK("mkdir /mydir", ret == 0);

	struct stat st;
	CHECK("stat /mydir after mkdir", stat("/mydir", &st) == 0);
	CHECK("new directory link count is 2", st.st_nlink == 2);

	ret = mkdir("/mydir/subdir", 0755);
	CHECK("mkdir /mydir/subdir", ret == 0);
	CHECK("stat /mydir after child mkdir", stat("/mydir", &st) == 0);
	CHECK("parent directory link count includes child directory", st.st_nlink == 3);
	CHECK("stat /mydir/subdir after mkdir", stat("/mydir/subdir", &st) == 0);
	CHECK("child directory link count is 2", st.st_nlink == 2);
	CHECK("rmdir /mydir/subdir", rmdir("/mydir/subdir") == 0);
	CHECK("stat /mydir after child rmdir", stat("/mydir", &st) == 0);
	CHECK("parent directory link count drops after rmdir", st.st_nlink == 2);

	/* Create a file inside the directory. */
	int fd = open("/mydir/file.txt", O_CREAT | O_WRONLY, 0644);
	CHECK("create /mydir/file.txt", fd >= 0);
	if (fd >= 0) {
		write(fd, "nested", 6);
		close(fd);
	}

	/* Read it back. */
	fd = open("/mydir/file.txt", O_RDONLY);
	CHECK("reopen /mydir/file.txt", fd >= 0);
	if (fd >= 0) {
		char buf[16] = {0};
		ssize_t nr = read(fd, buf, sizeof(buf) - 1);
		CHECK("read nested file", nr == 6);
		CHECK("data is 'nested'", memcmp(buf, "nested", 6) == 0);
		close(fd);
	}

	/* mkdir on existing path should fail. */
	ret = mkdir("/mydir", 0755);
	CHECK("mkdir on existing dir fails", ret != 0);

	CHECK("chdir nonexistent path fails", chdir("/missing_chdir_dir") != 0);
	CHECK("chdir regular file fails", chdir("/mydir/file.txt") != 0);
}

/*  Test 7: unlink  */

static void test_unlink(void) {
	printf("\n[test_unlink]\n");

	int fd = open("/test_unlink", O_CREAT | O_WRONLY, 0644);
	CHECK("create /test_unlink", fd >= 0);
	if (fd >= 0) {
		write(fd, "data", 4);
		close(fd);
	}

	int ret = unlink("/test_unlink");
	CHECK("unlink /test_unlink", ret == 0);

	/* Opening the unlinked file should fail. */
	fd = open("/test_unlink", O_RDONLY);
	CHECK("open after unlink fails", fd < 0);

	/* Unlink nonexistent should fail. */
	ret = unlink("/nonexistent");
	CHECK("unlink nonexistent fails", ret != 0);
}

/*  Test 8: fcntl F_GETFL  */

static void test_fcntl(void) {
	printf("\n[test_fcntl]\n");

	int fd = open("/test_fcntl", O_CREAT | O_RDWR, 0644);
	CHECK("create /test_fcntl", fd >= 0);
	if (fd < 0)
		return;

	int flags = fcntl(fd, F_GETFL);
	CHECK("fcntl F_GETFL returns O_RDWR", (flags & O_ACCMODE) == O_RDWR);

	int fdflags = fcntl(fd, F_GETFD);
	CHECK("fcntl F_GETFD starts clear", fdflags == 0);

	CHECK("fcntl F_SETFD sets FD_CLOEXEC", fcntl(fd, F_SETFD, FD_CLOEXEC) == 0);
	fdflags = fcntl(fd, F_GETFD);
	CHECK("fcntl F_GETFD reports FD_CLOEXEC", (fdflags & FD_CLOEXEC) != 0);

	CHECK("fcntl F_SETFD clears FD_CLOEXEC", fcntl(fd, F_SETFD, 0) == 0);
	fdflags = fcntl(fd, F_GETFD);
	CHECK("fcntl F_GETFD reports clear", fdflags == 0);

	int dupfd = fcntl(fd, F_DUPFD, 20);
	CHECK("fcntl F_DUPFD returns fd at least requested minimum", dupfd >= 20);
	if (dupfd >= 0) {
		CHECK("fcntl duplicated fd has same access mode",
		      (fcntl(dupfd, F_GETFL) & O_ACCMODE) == O_RDWR);
		close(dupfd);
	}

	close(fd);
}

/*  Test 9: Large write spanning multiple chunks  */

static void test_large_write(void) {
	printf("\n[test_large_write]\n");

	/* Write 3000 bytes — should span 3 chunks (1024 each). */
	char wbuf[3000];
	for (int i = 0; i < 3000; i++) {
		wbuf[i] = 'A' + (i % 26);
	}

	int fd = open("/test_large", O_CREAT | O_RDWR, 0644);
	CHECK("create /test_large", fd >= 0);
	if (fd < 0)
		return;

	ssize_t nw = write(fd, wbuf, 3000);
	CHECK("write 3000 bytes", nw == 3000);

	lseek(fd, 0, SEEK_SET);

	char rbuf[3000] = {0};
	ssize_t nr = read(fd, rbuf, 3000);
	CHECK("read 3000 bytes back", nr == 3000);
	CHECK("data matches", memcmp(rbuf, wbuf, 3000) == 0);

	close(fd);
}

/*  Test 10: Read at EOF returns 0  */

static void test_read_eof(void) {
	printf("\n[test_read_eof]\n");

	int fd = open("/test_eof", O_CREAT | O_RDWR, 0644);
	CHECK("create /test_eof", fd >= 0);
	if (fd < 0)
		return;

	write(fd, "hi", 2);

	/* Seek past end. */
	lseek(fd, 100, SEEK_SET);

	char buf[16];
	ssize_t nr = read(fd, buf, sizeof(buf));
	CHECK("read past EOF returns 0", nr == 0);

	close(fd);
}

static void test_sparse_write(void) {
	printf("\n[test_sparse_write]\n");

	int fd = open("/test_sparse", O_CREAT | O_RDWR, 0644);
	CHECK("create /test_sparse", fd >= 0);
	if (fd < 0)
		return;

	CHECK("seed sparse file", write(fd, "abc", 3) == 3);
	CHECK("seek beyond multiple chunks", lseek(fd, 3000, SEEK_SET) == 3000);
	CHECK("write after sparse seek", write(fd, "Z", 1) == 1);

	struct stat st;
	CHECK("fstat sparse file", fstat(fd, &st) == 0);
	CHECK("sparse write extends size", st.st_size == 3001);

	char buf[3001];
	memset(buf, 'X', sizeof(buf));
	CHECK("seek to start of sparse file", lseek(fd, 0, SEEK_SET) == 0);
	CHECK("read full sparse file", read(fd, buf, sizeof(buf)) == 3001);
	CHECK("prefix data preserved", memcmp(buf, "abc", 3) == 0);
	CHECK("early sparse hole reads as zero", buf[3] == '\0');
	CHECK("late sparse hole reads as zero", buf[2999] == '\0');
	CHECK("sparse data byte preserved", buf[3000] == 'Z');

	close(fd);
}

/*  Test 11: Write to stdout passes through (fd < 3)  */

static void test_stdout_passthrough(void) {
	printf("\n[test_stdout_passthrough]\n");

	/* This write should go to real stdout, not IMFS.
	 * If it prints, the passthrough works. */
	const char *msg = "  PASS: stdout passthrough works\n";
	ssize_t nw = write(1, msg, strlen(msg));
	tests_run++;
	if (nw > 0)
		tests_passed++;
}


static void test_fork(void) {
    printf("\n[test_fork]\n");
    
    int fd = open("fork-test", O_CREAT | O_RDWR, 0666);

    int pid = fork();
    char buffer[10] = "hello";

    if (pid == 0) {
    	ssize_t r = write(fd, buffer, 6);
        CHECK("Fork copies file descriptors", fcntl(fd, F_GETFD) != -1);	

	exit(0);
    } else {
    	wait(NULL);
    }

    close(fd);
    unlink("fork-test");
}

static void test_wrong_write(void) {
    printf("\n[test_wrong_write]\n");

    int fd = open(".", O_WRONLY | O_DIRECTORY);   // try opening directory for write

    int ret = write(fd, "x", 1);    // try writing
    CHECK("Block writes on directory.", ret == -1 && errno == 9);

    close(fd);
}

static void test_link_rw(void) {
	printf("\n[test_link_rw]\n");

	int fd = open("file1", O_CREAT | O_WRONLY, 0666);
	char buf[10] = "hello";

	int ret = write(fd, buf, 6);
	close(fd);

	struct stat st;
	CHECK("initial hard link count is 1", stat("file1", &st) == 0 && st.st_nlink == 1);
	CHECK("link file1 to file2", link("file1", "file2") == 0);
	CHECK("hard link count after link is 2", stat("file1", &st) == 0 && st.st_nlink == 2);

	fd = open("file2", O_RDONLY, 0666);

	char read_buf[10];
	ret = read(fd, read_buf, 6);
	close(fd);

	CHECK("Read linked file.", strcmp(buf, read_buf) == 0);

	fd = open("file2", O_WRONLY);
	memcpy(buf, "newstring", 10);
	write(fd, buf, 10);
	close(fd);

	fd = open("file1", O_RDONLY);
	read(fd, read_buf, 10);
	close(fd);

	CHECK("Write linked file.", strcmp(buf, read_buf) == 0);

	CHECK("unlink file1", unlink("file1") == 0);
	CHECK("remaining hard link count is 1", stat("file2", &st) == 0 && st.st_nlink == 1);
	CHECK("unlink file2", unlink("file2") == 0);
}

static void test_at_metadata_syscalls(void) {
	printf("\n[test_at_metadata_syscalls]\n");

	int ret = mkdir("/atdir", 0755);
	CHECK("mkdir /atdir for *at tests", ret == 0);

	int dirfd = open("/atdir", O_RDONLY | O_DIRECTORY);
	CHECK("open /atdir as dirfd", dirfd >= 0);
	if (dirfd < 0)
		return;

	int fd = openat(dirfd, "file", O_CREAT | O_RDWR, 0644);
	CHECK("openat creates file relative to dirfd", fd >= 0);
	if (fd >= 0) {
		CHECK("write openat file", write(fd, "atdata", 6) == 6);
		close(fd);
	}

	CHECK("faccessat sees relative file",
	      faccessat(dirfd, "file", F_OK, 0) == 0);

	struct stat st;
	memset(&st, 0, sizeof(st));
	CHECK("fstatat sees relative file",
	      fstatat(dirfd, "file", &st, 0) == 0);
	CHECK("fstatat reports regular file", S_ISREG(st.st_mode));

	CHECK("fchmodat updates mode",
	      fchmodat(dirfd, "file", 0600, 0) == 0);
	memset(&st, 0, sizeof(st));
	CHECK("fstatat after fchmodat",
	      fstatat(dirfd, "file", &st, 0) == 0);
	CHECK("mode after fchmodat is 0600", (st.st_mode & 0777) == 0600);

	CHECK("chown existing path succeeds",
	      chown("/atdir/file", getuid(), getgid()) == 0);
	CHECK("lchown existing path succeeds",
	      lchown("/atdir/file", getuid(), getgid()) == 0);
	CHECK("fchownat existing path succeeds",
	      fchownat(dirfd, "file", getuid(), getgid(), 0) == 0);

	CHECK("utimensat relative path succeeds",
	      utimensat(dirfd, "file", NULL, 0) == 0);

	CHECK("renameat relative path succeeds",
	      renameat(dirfd, "file", dirfd, "file2") == 0);
	CHECK("old name gone after renameat",
	      faccessat(dirfd, "file", F_OK, 0) != 0);
	CHECK("new name exists after renameat",
	      faccessat(dirfd, "file2", F_OK, 0) == 0);

	CHECK("unlinkat removes relative file",
	      unlinkat(dirfd, "file2", 0) == 0);
	CHECK("file gone after unlinkat",
	      faccessat(dirfd, "file2", F_OK, 0) != 0);

	close(dirfd);
	CHECK("rmdir removes empty *at test dir", rmdir("/atdir") == 0);
}

static void test_statfs(void) {
	printf("\n[test_statfs]\n");

	struct statfs sfs;
	int ret = statfs("/", &sfs);
	CHECK("statfs root succeeds", ret == 0);
	CHECK("statfs reports block size", ret == 0 && sfs.f_bsize > 0);
	CHECK("statfs reports blocks", ret == 0 && sfs.f_blocks > 0);
	CHECK("statfs reports name length", ret == 0 && sfs.f_namelen > 0);

	int fd = open("/test_statfs_file", O_CREAT | O_RDWR, 0644);
	CHECK("create /test_statfs_file", fd >= 0);
	if (fd >= 0) {
		memset(&sfs, 0, sizeof(sfs));
		ret = fstatfs(fd, &sfs);
		CHECK("fstatfs file succeeds", ret == 0);
		CHECK("fstatfs reports block size", ret == 0 && sfs.f_bsize > 0);
		close(fd);
	}

	ret = statfs("/missing_statfs_path", &sfs);
	CHECK("statfs nonexistent path fails", ret != 0);
}

static void test_sync_syscalls(void) {
	printf("\n[test_sync_syscalls]\n");

	int fd = open("/test_sync_syscalls", O_CREAT | O_RDWR, 0644);
	CHECK("create /test_sync_syscalls", fd >= 0);
	if (fd < 0)
		return;

	CHECK("write sync test data", write(fd, "wal", 3) == 3);
	CHECK("fsync succeeds", fsync(fd) == 0);
	CHECK("fdatasync succeeds", fdatasync(fd) == 0);
	CHECK("sync_file_range succeeds", sync_file_range(fd, 0, 3, 0) == 0);

	close(fd);
	unlink("/test_sync_syscalls");
}

/*  Test N: mmap basic round-trip.
 *
 *  Postgres' dyn-shm pattern: open → ftruncate → mmap → use.  This
 *  exercises imfs's lazy Reg→RegMapped promotion (first mmap call
 *  triggers the drain), and verifies that bytes written via the
 *  mapping are subsequently readable via read(fd).
 */

static void test_mmap_basic(void) {
	printf("\n[test_mmap_basic]\n");

	const size_t SZ = 4096;
	int fd = open("/mmap_basic", O_CREAT | O_RDWR, 0644);
	CHECK("open /mmap_basic", fd >= 0);
	if (fd < 0) return;

	int rc = ftruncate(fd, SZ);
	CHECK("ftruncate to 4096", rc == 0);

	void *addr =
	    mmap(NULL, SZ, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	CHECK("mmap returns non-MAP_FAILED", addr != MAP_FAILED);
	if (addr == MAP_FAILED) { close(fd); return; }

	/* Write a pattern through the mapping. */
	memcpy(addr, "hello mmap world", 16);
	((char *)addr)[100] = 'Z';

	/* Read back via the fd — should see the writes. */
	char buf[128] = {0};
	off_t pos = lseek(fd, 0, SEEK_SET);
	CHECK("lseek back to 0", pos == 0);
	ssize_t nr = read(fd, buf, sizeof(buf));
	CHECK("read returns >= 101 bytes", nr >= 101);
	CHECK("read sees mapping write at offset 0",
	      memcmp(buf, "hello mmap world", 16) == 0);
	CHECK("read sees mapping write at offset 100", buf[100] == 'Z');

	rc = munmap(addr, SZ);
	CHECK("munmap returns 0", rc == 0);

	close(fd);
	unlink("/mmap_basic");
}

/*  Test N+1: ftruncate shrink zeros the tail bytes.
 *
 *  Verifies the shrink-zeroing behavior we added to truncate_node:
 *  bytes past the new EOF must read as zeros (Linux SIGBUSes
 *  instead, but we degrade to zeros for graceful behavior).
 */

static void test_mmap_truncate_shrink_zeros(void) {
	printf("\n[test_mmap_truncate_shrink_zeros]\n");

	const size_t SZ = 4096;
	int fd = open("/mmap_shrink", O_CREAT | O_RDWR, 0644);
	CHECK("open /mmap_shrink", fd >= 0);
	if (fd < 0) return;
	if (ftruncate(fd, SZ) != 0) { close(fd); return; }

	void *addr =
	    mmap(NULL, SZ, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	CHECK("mmap returns non-MAP_FAILED", addr != MAP_FAILED);
	if (addr == MAP_FAILED) { close(fd); return; }

	/* Fill the whole region with 0xAB. */
	memset(addr, 0xAB, SZ);

	/* Shrink to 1024 bytes — bytes [1024, 4096) should be zeroed. */
	int rc = ftruncate(fd, 1024);
	CHECK("ftruncate shrink to 1024", rc == 0);

	int tail_zeroed = 1;
	for (size_t i = 1024; i < SZ; i++) {
		if (((unsigned char *)addr)[i] != 0) {
			tail_zeroed = 0;
			break;
		}
	}
	CHECK("bytes past new EOF are zeroed via mapping", tail_zeroed);

	/* Head bytes [0, 1024) should still hold the 0xAB pattern. */
	int head_intact = 1;
	for (size_t i = 0; i < 1024; i++) {
		if (((unsigned char *)addr)[i] != 0xAB) {
			head_intact = 0;
			break;
		}
	}
	CHECK("bytes before new EOF are unchanged", head_intact);

	munmap(addr, SZ);
	close(fd);
	unlink("/mmap_shrink");
}

/*  Test N+2: mmap shared across fork.
 *
 *  Parent maps the file with MAP_SHARED, then forks.  Child writes
 *  through the mapping, parent reads after waitpid and should see
 *  the child's writes.  This is the cross-cage MAP_SHARED semantic
 *  the imfs design relies on for postgres' dyn-shm.
 */

static void test_mmap_shared_fork(void) {
	printf("\n[test_mmap_shared_fork]\n");

	const size_t SZ = 4096;
	int fd = open("/mmap_shared", O_CREAT | O_RDWR, 0644);
	CHECK("open /mmap_shared", fd >= 0);
	if (fd < 0) return;
	if (ftruncate(fd, SZ) != 0) { close(fd); return; }

	void *addr =
	    mmap(NULL, SZ, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	CHECK("parent mmap", addr != MAP_FAILED);
	if (addr == MAP_FAILED) { close(fd); return; }

	memcpy(addr, "PARENT WROTE   ", 16);

	pid_t pid = fork();
	if (pid == 0) {
		/* Child sees the parent's bytes through the same
		 * MAP_SHARED region, then overwrites. */
		if (memcmp(addr, "PARENT WROTE   ", 16) != 0) {
			_exit(2);
		}
		memcpy(addr, "CHILD WROTE    ", 16);
		_exit(0);
	}

	int status = 0;
	waitpid(pid, &status, 0);
	CHECK("child saw parent's writes", WIFEXITED(status) && WEXITSTATUS(status) == 0);
	CHECK("parent sees child's writes via shared mapping",
	      memcmp(addr, "CHILD WROTE    ", 16) == 0);

	munmap(addr, SZ);
	close(fd);
	unlink("/mmap_shared");
}

/*  Test N+3: munmap drops the mmap_refs counter.
 *
 *  Indirect check via a follow-up ftruncate grow: after the cage
 *  has mmap'd then munmap'd, ftruncate should be allowed to grow
 *  the region (which would fail with EBUSY if mmap_refs were still
 *  positive).
 */

static void test_mmap_refcount_release(void) {
	printf("\n[test_mmap_refcount_release]\n");

	int fd = open("/mmap_refs", O_CREAT | O_RDWR, 0644);
	CHECK("open /mmap_refs", fd >= 0);
	if (fd < 0) return;
	if (ftruncate(fd, 4096) != 0) { close(fd); return; }

	void *addr =
	    mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	CHECK("mmap succeeds", addr != MAP_FAILED);
	if (addr == MAP_FAILED) { close(fd); return; }

	int rc = munmap(addr, 4096);
	CHECK("munmap succeeds", rc == 0);

	/* After munmap, mmap_refs should be back to 0, so a grow is
	 * allowed.  If we leaked the refcount, this fails. */
	rc = ftruncate(fd, 16384);
	CHECK("ftruncate grow after munmap succeeds", rc == 0);

	close(fd);
	unlink("/mmap_refs");
}

/*  Test N+4: fd I/O outside a live mmap.
 *
 *  PostgreSQL can keep a small mapping live while later fd reads/writes
 *  touch byte ranges outside that mapping. IMFS must mirror only the
 *  overlapping part of a live mmap; it must not treat the mapping as if
 *  it covers the whole file.
 */

static void test_mmap_fd_io_outside_live_mapping(void) {
	printf("\n[test_mmap_fd_io_outside_live_mapping]\n");

	const size_t MAP_SZ = 4096;
	const size_t FILE_SZ = 65536;
	const off_t OUTSIDE_OFF = 32768;
	char write_buf[8192];
	char read_buf[8192];

	memset(write_buf, 'Q', sizeof(write_buf));
	memset(read_buf, 0, sizeof(read_buf));

	int fd = open("/mmap_outside_live", O_CREAT | O_RDWR, 0644);
	CHECK("open /mmap_outside_live", fd >= 0);
	if (fd < 0) return;

	CHECK("ftruncate large file", ftruncate(fd, FILE_SZ) == 0);

	void *addr =
	    mmap(NULL, MAP_SZ, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	CHECK("mmap small live range", addr != MAP_FAILED);
	if (addr == MAP_FAILED) { close(fd); return; }

	memcpy(addr, "live mapping", 12);

	ssize_t nw = pwrite(fd, write_buf, sizeof(write_buf), OUTSIDE_OFF);
	CHECK("pwrite outside live mmap range", nw == (ssize_t)sizeof(write_buf));

	ssize_t nr = pread(fd, read_buf, sizeof(read_buf), OUTSIDE_OFF);
	CHECK("pread outside live mmap range", nr == (ssize_t)sizeof(read_buf));
	CHECK("pread sees outside fd write",
	      memcmp(read_buf, write_buf, sizeof(write_buf)) == 0);
	CHECK("live mapping remains valid",
	      memcmp(addr, "live mapping", 12) == 0);

	CHECK("munmap outside-live test", munmap(addr, MAP_SZ) == 0);
	close(fd);
	unlink("/mmap_outside_live");
}

/*  Test N+5: unlink and close while mmap is still live.
 *
 *  A doomed mapped file must not be reclaimed until the final munmap
 *  releases mmap_refs. This mirrors postgres DSM cleanup paths where
 *  descriptors and names can disappear before the mapping itself.
 */

static void test_mmap_unlink_close_while_live(void) {
	printf("\n[test_mmap_unlink_close_while_live]\n");

	const size_t MAP_SZ = 4096;

	int fd = open("/mmap_unlink_live", O_CREAT | O_RDWR, 0644);
	CHECK("open /mmap_unlink_live", fd >= 0);
	if (fd < 0) return;

	CHECK("ftruncate unlink-live file", ftruncate(fd, MAP_SZ) == 0);

	void *addr =
	    mmap(NULL, MAP_SZ, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	CHECK("mmap unlink-live file", addr != MAP_FAILED);
	if (addr == MAP_FAILED) { close(fd); unlink("/mmap_unlink_live"); return; }

	memcpy(addr, "mapped after unlink", 19);

	CHECK("unlink while mmap is live", unlink("/mmap_unlink_live") == 0);
	CHECK("close while mmap is live", close(fd) == 0);
	CHECK("live mapping remains readable after unlink and close",
	      memcmp(addr, "mapped after unlink", 19) == 0);
	CHECK("munmap after unlink and close", munmap(addr, MAP_SZ) == 0);
}

/*  Main  */

int main(void) {
	printf("=== imfs grate test ===\n");

	test_open_nocreat();
	test_basic_rw();
	test_append();
	test_pread_pwrite();
	test_mkdir();
	test_unlink();
	test_fcntl();
	test_large_write();
	test_read_eof();
	test_sparse_write();
	test_stdout_passthrough();
	test_fork();
	test_wrong_write();
	test_link_rw();
	test_at_metadata_syscalls();
	test_lseek();
	test_statfs();
	test_sync_syscalls();
	test_mmap_basic();
	test_mmap_truncate_shrink_zeros();
	test_mmap_shared_fork();
	test_mmap_refcount_release();
	test_mmap_fd_io_outside_live_mapping();
	test_mmap_unlink_close_while_live();

	printf("\n=== results: %d/%d passed ===\n", tests_passed, tests_run);
	return (tests_passed == tests_run) ? 0 : 1;
}
