/*
 * mTLS grate test suite.
 *
 * Verifies that the mTLS grate transparently encrypts/decrypts traffic
 * without corrupting data. The cage does plain TCP — the grate wraps it
 * in TLS. Tests cover data integrity, edge cases, and non-TLS passthrough.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#define PORT_BASE 4430
#define BUF_SIZE 8192

static int tests_run = 0;
static int tests_passed = 0;

#define CHECK(name, expr) do { \
    tests_run++; \
    if (expr) { printf("  PASS: %s\n", name); tests_passed++; } \
    else { printf("  FAIL: %s (errno=%d)\n", name, errno); } \
} while (0)

static struct sockaddr_in make_addr(int port) {
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return a;
}

static int make_server(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr = make_addr(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) { close(fd); return -1; }
    if (listen(fd, 5) < 0) { close(fd); return -1; }
    return fd;
}

/* ================================================================
 * Test 1: Basic round-trip — client writes, server reads, responds
 * ================================================================ */
static void test_basic_roundtrip(void) {
    printf("\n[test_basic_roundtrip]\n");
    int port = PORT_BASE;
    int server = make_server(port);
    CHECK("server setup", server >= 0);
    if (server < 0) return;

    pid_t pid = fork();
    if (pid == 0) {
        close(server);
        int c = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in a = make_addr(port);
        if (connect(c, (struct sockaddr *)&a, sizeof(a)) < 0) _exit(1);

        const char *msg = "Hello from client";
        if (write(c, msg, strlen(msg)) != (ssize_t)strlen(msg)) _exit(1);

        char buf[BUF_SIZE] = {0};
        ssize_t n = read(c, buf, sizeof(buf) - 1);
        if (n <= 0 || strstr(buf, "Hello from server") == NULL) _exit(1);

        close(c);
        _exit(0);
    }

    int conn = accept(server, NULL, NULL);
    CHECK("accept", conn >= 0);
    if (conn >= 0) {
        char buf[BUF_SIZE] = {0};
        ssize_t n = read(conn, buf, sizeof(buf) - 1);
        CHECK("read client msg", n > 0 && strstr(buf, "Hello from client") != NULL);

        const char *resp = "Hello from server";
        ssize_t w = write(conn, resp, strlen(resp));
        CHECK("write response", w == (ssize_t)strlen(resp));
        close(conn);
    }

    int status;
    waitpid(pid, &status, 0);
    CHECK("child exit", WIFEXITED(status) && WEXITSTATUS(status) == 0);
    close(server);
}

/* ================================================================
 * Test 2: Large payload — 64KB write/read integrity
 * ================================================================ */
static void test_large_payload(void) {
    printf("\n[test_large_payload]\n");
    int port = PORT_BASE + 1;
    int server = make_server(port);
    CHECK("server setup", server >= 0);
    if (server < 0) return;

    #define LARGE_SIZE (64 * 1024)

    pid_t pid = fork();
    if (pid == 0) {
        close(server);
        int c = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in a = make_addr(port);
        if (connect(c, (struct sockaddr *)&a, sizeof(a)) < 0) _exit(1);

        /* Write 64KB with a known pattern */
        char *big = malloc(LARGE_SIZE);
        for (int i = 0; i < LARGE_SIZE; i++) big[i] = (char)(i & 0xFF);

        ssize_t total = 0;
        while (total < LARGE_SIZE) {
            ssize_t n = write(c, big + total, LARGE_SIZE - total);
            if (n <= 0) break;
            total += n;
        }
        free(big);
        close(c);
        _exit(total == LARGE_SIZE ? 0 : 1);
    }

    int conn = accept(server, NULL, NULL);
    CHECK("accept", conn >= 0);
    if (conn >= 0) {
        char *big = malloc(LARGE_SIZE);
        ssize_t total = 0;
        while (total < LARGE_SIZE) {
            ssize_t n = read(conn, big + total, LARGE_SIZE - total);
            if (n <= 0) break;
            total += n;
        }
        CHECK("read 64KB", total == LARGE_SIZE);

        int corrupt = 0;
        for (int i = 0; i < LARGE_SIZE; i++) {
            if (big[i] != (char)(i & 0xFF)) { corrupt = 1; break; }
        }
        CHECK("64KB data integrity", !corrupt);
        free(big);
        close(conn);
    }

    int status;
    waitpid(pid, &status, 0);
    CHECK("child wrote all", WIFEXITED(status) && WEXITSTATUS(status) == 0);
    close(server);
}

/* ================================================================
 * Test 3: Multiple sequential messages on one connection
 * ================================================================ */
static void test_multiple_messages(void) {
    printf("\n[test_multiple_messages]\n");
    int port = PORT_BASE + 2;
    int server = make_server(port);
    CHECK("server setup", server >= 0);
    if (server < 0) return;

    #define NUM_MSGS 20

    pid_t pid = fork();
    if (pid == 0) {
        close(server);
        int c = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in a = make_addr(port);
        if (connect(c, (struct sockaddr *)&a, sizeof(a)) < 0) _exit(1);

        for (int i = 0; i < NUM_MSGS; i++) {
            char msg[64];
            int len = snprintf(msg, sizeof(msg), "msg-%03d", i);
            if (write(c, msg, len) != len) _exit(1);
        }
        close(c);
        _exit(0);
    }

    int conn = accept(server, NULL, NULL);
    CHECK("accept", conn >= 0);
    if (conn >= 0) {
        char buf[BUF_SIZE] = {0};
        ssize_t total = 0;
        while (total < BUF_SIZE - 1) {
            ssize_t n = read(conn, buf + total, BUF_SIZE - 1 - total);
            if (n <= 0) break;
            total += n;
        }

        /* All messages should be in the buffer (TCP stream) */
        CHECK("received data", total > 0);
        CHECK("first msg present", strstr(buf, "msg-000") != NULL);
        CHECK("last msg present", strstr(buf, "msg-019") != NULL);
        close(conn);
    }

    int status;
    waitpid(pid, &status, 0);
    CHECK("child exit", WIFEXITED(status) && WEXITSTATUS(status) == 0);
    close(server);
}

/* ================================================================
 * Test 4: Zero-byte write — should succeed without error
 * ================================================================ */
static void test_zero_write(void) {
    printf("\n[test_zero_write]\n");
    int port = PORT_BASE + 3;
    int server = make_server(port);
    CHECK("server setup", server >= 0);
    if (server < 0) return;

    pid_t pid = fork();
    if (pid == 0) {
        close(server);
        int c = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in a = make_addr(port);
        if (connect(c, (struct sockaddr *)&a, sizeof(a)) < 0) _exit(1);

        ssize_t n = write(c, "", 0);
        if (n != 0) _exit(1);

        /* Follow up with real data to prove connection still works */
        n = write(c, "after-zero", 10);
        if (n != 10) _exit(1);

        close(c);
        _exit(0);
    }

    int conn = accept(server, NULL, NULL);
    CHECK("accept", conn >= 0);
    if (conn >= 0) {
        char buf[64] = {0};
        ssize_t n = read(conn, buf, sizeof(buf) - 1);
        CHECK("read after zero-byte write", n == 10 && memcmp(buf, "after-zero", 10) == 0);
        close(conn);
    }

    int status;
    waitpid(pid, &status, 0);
    CHECK("child exit", WIFEXITED(status) && WEXITSTATUS(status) == 0);
    close(server);
}

/* ================================================================
 * Test 5: File I/O passthrough — non-TLS fd unaffected
 * ================================================================ */
static void test_file_passthrough(void) {
    printf("\n[test_file_passthrough]\n");

    int fd = open("/tmp/mtls_test_file.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
    CHECK("open file", fd >= 0);
    if (fd < 0) return;

    const char *data = "file data not encrypted";
    ssize_t n = write(fd, data, strlen(data));
    CHECK("write to file", n == (ssize_t)strlen(data));

    lseek(fd, 0, SEEK_SET);
    char buf[64] = {0};
    n = read(fd, buf, sizeof(buf) - 1);
    CHECK("read from file", n == (ssize_t)strlen(data));
    CHECK("file data intact", memcmp(buf, data, strlen(data)) == 0);

    close(fd);
    unlink("/tmp/mtls_test_file.txt");
}

/* ================================================================
 * Test 6: Write then immediate close — clean shutdown
 * ================================================================ */
static void test_write_then_close(void) {
    printf("\n[test_write_then_close]\n");
    int port = PORT_BASE + 4;
    int server = make_server(port);
    CHECK("server setup", server >= 0);
    if (server < 0) return;

    pid_t pid = fork();
    if (pid == 0) {
        close(server);
        int c = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in a = make_addr(port);
        if (connect(c, (struct sockaddr *)&a, sizeof(a)) < 0) _exit(1);

        write(c, "goodbye", 7);
        close(c); /* immediate close after write */
        _exit(0);
    }

    int conn = accept(server, NULL, NULL);
    CHECK("accept", conn >= 0);
    if (conn >= 0) {
        char buf[64] = {0};
        ssize_t n = read(conn, buf, sizeof(buf) - 1);
        CHECK("read before close", n == 7 && memcmp(buf, "goodbye", 7) == 0);

        /* Next read should return 0 (EOF) since client closed */
        n = read(conn, buf, sizeof(buf));
        CHECK("EOF after client close", n == 0);
        close(conn);
    }

    int status;
    waitpid(pid, &status, 0);
    CHECK("child exit", WIFEXITED(status) && WEXITSTATUS(status) == 0);
    close(server);
}

/* ================================================================
 * Test 7: Bidirectional exchange — interleaved reads and writes
 * ================================================================ */
static void test_bidirectional(void) {
    printf("\n[test_bidirectional]\n");
    int port = PORT_BASE + 5;
    int server = make_server(port);
    CHECK("server setup", server >= 0);
    if (server < 0) return;

    pid_t pid = fork();
    if (pid == 0) {
        close(server);
        int c = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in a = make_addr(port);
        if (connect(c, (struct sockaddr *)&a, sizeof(a)) < 0) _exit(1);

        char buf[64] = {0};
        for (int i = 0; i < 5; i++) {
            char msg[32];
            int len = snprintf(msg, sizeof(msg), "ping-%d", i);
            if (write(c, msg, len) != len) _exit(1);

            ssize_t n = read(c, buf, sizeof(buf) - 1);
            if (n <= 0) _exit(1);
            buf[n] = 0;

            char expected[32];
            snprintf(expected, sizeof(expected), "pong-%d", i);
            if (strstr(buf, expected) == NULL) _exit(1);
        }

        close(c);
        _exit(0);
    }

    int conn = accept(server, NULL, NULL);
    CHECK("accept", conn >= 0);
    if (conn >= 0) {
        int ok = 1;
        for (int i = 0; i < 5; i++) {
            char buf[64] = {0};
            ssize_t n = read(conn, buf, sizeof(buf) - 1);
            if (n <= 0) { ok = 0; break; }

            char expected[32];
            snprintf(expected, sizeof(expected), "ping-%d", i);
            if (strstr(buf, expected) == NULL) { ok = 0; break; }

            char resp[32];
            int len = snprintf(resp, sizeof(resp), "pong-%d", i);
            if (write(conn, resp, len) != len) { ok = 0; break; }
        }
        CHECK("5 ping-pong exchanges", ok);
        close(conn);
    }

    int status;
    waitpid(pid, &status, 0);
    CHECK("child exit", WIFEXITED(status) && WEXITSTATUS(status) == 0);
    close(server);
}

/* ================================================================ */

int main(void) {
    printf("=== mTLS Grate Test Suite ===\n");

    test_basic_roundtrip();
    test_large_payload();
    test_multiple_messages();
    test_zero_write();
    test_file_passthrough();
    test_write_then_close();
    test_bidirectional();

    printf("\n=== Result: %d/%d passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
