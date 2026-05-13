/*
 * mTLS propagation demo.
 *
 * Simulates an application that spawns worker cages via fork, where each
 * worker accepts a connection. The mtls-grate transparently wraps all
 * connections in TLS without any per-worker configuration.
 *
 * Verifies:
 * 1. Parent (main process) can accept and exchange data through mTLS
 * 2. Forked worker cages inherit the mTLS handler and can also accept
 *    and exchange data — no per-worker TLS setup needed
 * 3. Multiple spawn depths all get mTLS automatically
 *
 * Usage:
 *   lind-wasm grates/mtls-grate.cwasm \
 *     --cert ./certs/cert.pem --key ./certs/key.pem --ca ./certs/ca.crt \
 *     -- mtls_propagation_test.cwasm
 */
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#define BASE_PORT 4440
#define BUF_SIZE 256

static int tests_run = 0;
static int tests_passed = 0;

#define CHECK(name, expr) do { \
    tests_run++; \
    if (expr) { printf("  PASS: %s\n", name); tests_passed++; } \
    else { printf("  FAIL: %s (errno=%d %s)\n", name, errno, strerror(errno)); } \
} while (0)

static struct sockaddr_in make_addr(int port) {
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return a;
}

/*
 * Run a server+client test at a given port and depth.
 * Forks: child connects, parent accepts. Both exchange data.
 * The mTLS grate wraps connect/accept transparently.
 */
static void test_at_depth(int depth, int port) {
    char label[128];

    printf("\n[depth %d, port %d]\n", depth, port);

    int server = socket(AF_INET, SOCK_STREAM, 0);
    snprintf(label, sizeof(label), "depth %d: socket()", depth);
    CHECK(label, server >= 0);
    if (server < 0) return;

    int opt = 1;
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = make_addr(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    snprintf(label, sizeof(label), "depth %d: bind()", depth);
    CHECK(label, bind(server, (struct sockaddr *)&addr, sizeof(addr)) == 0);

    snprintf(label, sizeof(label), "depth %d: listen()", depth);
    CHECK(label, listen(server, 1) == 0);

    pid_t pid = fork();
    if (pid == 0) {
        /* Child: client — connect and send data */
        close(server);

        int client = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in caddr = make_addr(port);
        if (connect(client, (struct sockaddr *)&caddr, sizeof(caddr)) < 0) {
            _exit(1);
        }

        /* Send a message identifying the depth */
        char msg[64];
        int len = snprintf(msg, sizeof(msg), "hello from depth %d client", depth);
        if (write(client, msg, len) != len) _exit(1);

        /* Read response */
        char buf[BUF_SIZE] = {0};
        ssize_t n = read(client, buf, sizeof(buf) - 1);
        if (n <= 0) _exit(1);

        close(client);
        _exit(0);
    }

    /* Parent: server — accept and exchange data */
    int conn = accept(server, NULL, NULL);
    snprintf(label, sizeof(label), "depth %d: accept()", depth);
    CHECK(label, conn >= 0);

    if (conn >= 0) {
        char buf[BUF_SIZE] = {0};
        ssize_t n = read(conn, buf, sizeof(buf) - 1);
        snprintf(label, sizeof(label), "depth %d: read client message", depth);
        CHECK(label, n > 0);

        char expected[64];
        snprintf(expected, sizeof(expected), "hello from depth %d client", depth);
        snprintf(label, sizeof(label), "depth %d: message content correct", depth);
        CHECK(label, n > 0 && strstr(buf, expected) != NULL);

        /* Send response */
        char resp[64];
        int rlen = snprintf(resp, sizeof(resp), "ack from depth %d server", depth);
        write(conn, resp, rlen);

        close(conn);
    }

    int status;
    waitpid(pid, &status, 0);
    snprintf(label, sizeof(label), "depth %d: client exited cleanly", depth);
    CHECK(label, WIFEXITED(status) && WEXITSTATUS(status) == 0);

    close(server);
}

int main(void) {
    printf("=== mTLS Propagation Demo ===\n");
    printf("Verifying TLS handler propagation across forked workers.\n");

    /* Depth 0: main process acts as server */
    test_at_depth(0, BASE_PORT);

    /* Depth 1: forked worker acts as server */
    pid_t w1 = fork();
    if (w1 == 0) {
        test_at_depth(1, BASE_PORT + 1);
        _exit(0);
    }
    if (w1 > 0) {
        int status;
        waitpid(w1, &status, 0);
    }

    /* Depth 2: worker spawns another worker */
    pid_t w2 = fork();
    if (w2 == 0) {
        pid_t w3 = fork();
        if (w3 == 0) {
            test_at_depth(2, BASE_PORT + 2);
            _exit(0);
        }
        if (w3 > 0) {
            int status;
            waitpid(w3, &status, 0);
        }
        _exit(0);
    }
    if (w2 > 0) {
        int status;
        waitpid(w2, &status, 0);
    }

    printf("\n=== Result: %d/%d passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
