/*
 * Postgres-style DSM demo.
 *
 * Composition: fs-routing-clamp routes /tmp to imfs.  No fs-view-grate
 * — all cages share one imfs, which is what we want for cross-cage
 * shared memory.
 *
 * Pattern (matches postgres' dynamic shared memory setup):
 *   1. Parent creates /tmp/dsm_segment in imfs, ftruncate to one page,
 *      mmap(MAP_SHARED, fd).
 *   2. Parent writes "parent_init" at offset 0.
 *   3. Parent fork()s twice — N=3 cooperating processes total.
 *   4. Each child opens /tmp/dsm_segment from imfs, mmaps it, writes a
 *      child-specific marker at a distinct offset.  Children do NOT
 *      reuse the parent's inherited mapping — they call mmap() again
 *      themselves, like postgres workers do when they attach to a DSM
 *      segment by name.
 *   5. Parent waits on both children and verifies its own mapping
 *      shows all three markers (its init + both children's).
 *   6. munmap / close / unlink.
 *
 * Usage:
 *   lind-wasm grates/fs-routing-clamp.cwasm --prefix /tmp %{ \
 *     grates/imfs-grate.cwasm \
 *   %} dsm_shared_test.cwasm
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define SEG_PATH    "/tmp/dsm_segment"
#define BASIC_PATH  "/tmp/mmap_basic"
#define SEG_SIZE    4096
#define OFF_PARENT  0
#define OFF_CHILD_A 1024
#define OFF_CHILD_B 2048
#define MARK_PARENT "parent_init"
#define MARK_A      "child_A"
#define MARK_B      "child_B"

static int tests_run = 0;
static int tests_passed = 0;

#define CHECK(name, expr) do { \
    tests_run++; \
    if (expr) { printf("  PASS: %s\n", name); tests_passed++; } \
    else { printf("  FAIL: %s (errno=%d %s)\n", name, errno, strerror(errno)); } \
} while (0)

static int basic_mmap_round_trip(void) {
    int fd = open(BASIC_PATH, O_CREAT | O_RDWR | O_TRUNC, 0644);
    CHECK("basic: create " BASIC_PATH, fd >= 0);
    if (fd < 0) return -1;

    CHECK("basic: ftruncate to one page", ftruncate(fd, SEG_SIZE) == 0);

    void *addr = mmap(NULL, SEG_SIZE, PROT_READ | PROT_WRITE,
                      MAP_SHARED, fd, 0);
    CHECK("basic: mmap MAP_SHARED", addr != MAP_FAILED);
    if (addr == MAP_FAILED) {
        close(fd);
        return -1;
    }

    memcpy(addr, "hello mmap world", 16);
    ((char *)addr)[100] = 'Z';

    char buf[128] = {0};
    CHECK("basic: lseek back to start", lseek(fd, 0, SEEK_SET) == 0);
    ssize_t nr = read(fd, buf, sizeof(buf));
    CHECK("basic: read sees mmap writes", nr >= 101 &&
          memcmp(buf, "hello mmap world", 16) == 0 &&
          buf[100] == 'Z');

    CHECK("basic: munmap", munmap(addr, SEG_SIZE) == 0);
    close(fd);
    unlink(BASIC_PATH);
    return 0;
}

/* Child body: open the segment by name, mmap it independently of the
 * inherited mapping, write the marker at the given offset, exit. */
static void child_body(const char *mark, size_t mark_len, off_t off) {
    int fd = open(SEG_PATH, O_RDWR);
    if (fd < 0) _exit(10);
    void *addr = mmap(NULL, SEG_SIZE, PROT_READ | PROT_WRITE,
                      MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED) _exit(11);

    memcpy((char *)addr + off, mark, mark_len);

    if (munmap(addr, SEG_SIZE) != 0) _exit(12);
    close(fd);
    _exit(0);
}

int main(void) {
    printf("=== DSM shared-mmap demo (parent + 2 children) ===\n");

    mkdir("/tmp", 0755);

    basic_mmap_round_trip();

    /* 1. Parent creates the segment. */
    int fd = open(SEG_PATH, O_CREAT | O_RDWR | O_TRUNC, 0644);
    CHECK("parent: create " SEG_PATH, fd >= 0);
    if (fd < 0) return 1;

    CHECK("parent: ftruncate to one page", ftruncate(fd, SEG_SIZE) == 0);

    /* 2. Parent mmaps and writes its sentinel. */
    void *addr = mmap(NULL, SEG_SIZE, PROT_READ | PROT_WRITE,
                      MAP_SHARED, fd, 0);
    CHECK("parent: mmap MAP_SHARED", addr != MAP_FAILED);
    if (addr == MAP_FAILED) { close(fd); return 1; }

    memcpy((char *)addr + OFF_PARENT, MARK_PARENT, sizeof(MARK_PARENT) - 1);

    /* 3. Fork two children.  Each will independently mmap the segment
     *    by name and stamp its marker at its own offset. */
    pid_t pids[2];
    pids[0] = fork();
    if (pids[0] == 0) {
        child_body(MARK_A, sizeof(MARK_A) - 1, OFF_CHILD_A);
    }
    pids[1] = fork();
    if (pids[1] == 0) {
        child_body(MARK_B, sizeof(MARK_B) - 1, OFF_CHILD_B);
    }

    /* 4. Wait for both children. */
    int status_a = -1, status_b = -1;
    waitpid(pids[0], &status_a, 0);
    waitpid(pids[1], &status_b, 0);
    CHECK("child A exited cleanly",
          WIFEXITED(status_a) && WEXITSTATUS(status_a) == 0);
    CHECK("child B exited cleanly",
          WIFEXITED(status_b) && WEXITSTATUS(status_b) == 0);

    /* 5. Parent reads through its inherited mapping and verifies all
     *    three markers are present.  Each was written by a different
     *    process — proves the segment is genuinely shared. */
    CHECK("parent sees its own sentinel at offset 0",
          memcmp((char *)addr + OFF_PARENT,
                 MARK_PARENT, sizeof(MARK_PARENT) - 1) == 0);
    CHECK("parent sees child A's marker at offset 1024",
          memcmp((char *)addr + OFF_CHILD_A,
                 MARK_A, sizeof(MARK_A) - 1) == 0);
    CHECK("parent sees child B's marker at offset 2048",
          memcmp((char *)addr + OFF_CHILD_B,
                 MARK_B, sizeof(MARK_B) - 1) == 0);

    /* 6. Cleanup. */
    CHECK("parent: munmap", munmap(addr, SEG_SIZE) == 0);
    close(fd);
    unlink(SEG_PATH);

    printf("\n=== Result: %d/%d passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
