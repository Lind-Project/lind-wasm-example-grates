#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>

// # Provide input via echo
// echo "test input" | ./strace
// # Or run with strace and provide input
// echo "hello world" | strace -e trace=read ./strace

// Test syscalls: read (0), write (1), open (2), close (3), geteuid (107)
int main(int argc, char *argv[]) {
    // Test 1: read syscall (0)
    printf("[Cage | Test 1] Testing read syscall\n");
    char buffer[100];
    ssize_t ret = read(0, buffer, sizeof(buffer) - 1);
    if (ret > 0) {
        buffer[ret] = '\0';
        printf("[Cage | read] read ret = %zd, buffer = %s\n", ret, buffer);
    } else if (ret == 0) {
        printf("[Cage | read] read ret = 0 (EOF)\n");
    } else {
        printf("[Cage | read] read ret = %zd (error: %s)\n", ret, strerror(errno));
    }
    
    // Test 2: write syscall (1)
    printf("[Cage | Test 2] Testing write syscall\n");
    const char *write_msg = "Hello from write syscall\n";
    ssize_t write_ret = write(1, write_msg, 25);
    if (write_ret >= 0) {
        printf("[Cage | write] write ret = %zd\n", write_ret);
    } else {
        printf("[Cage | write] write ret = %zd (error: %s)\n", write_ret, strerror(errno));
    }
    
    // Test 3: open syscall (2)
    printf("[Cage | Test 3] Testing open syscall\n");
    const char *test_file = "/tmp/strace_test_file";
    int fd = open(test_file, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) {
        printf("[Cage | open] open ret = %d (file descriptor)\n", fd);
    } else {
        printf("[Cage | open] open ret = %d (error: %s)\n", fd, strerror(errno));
        fd = -1; // Ensure fd is invalid for close test
    }
    
    // Test 4: close syscall (3)
    printf("[Cage | Test 4] Testing close syscall\n");
    if (fd >= 0) {
        int close_ret = close(fd);
        if (close_ret == 0) {
            printf("[Cage | close] close ret = 0 (success)\n");
        } else {
            printf("[Cage | close] close ret = %d (error: %s)\n", close_ret, strerror(errno));
        }
    } else {
        printf("[Cage | close] Skipping close test (no valid file descriptor)\n");
    }
    
    // Test 5: geteuid syscall (107)
    printf("[Cage | Test 5] Testing geteuid syscall\n");
    uid_t euid = geteuid();
    printf("[Cage | geteuid] geteuid ret = %u (effective user ID)\n", euid);
    
    return 0;
}

