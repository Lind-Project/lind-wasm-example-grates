/*
 * Test for net-namespace-grate-rs.
 *
 * Run with testing-grate as the clamped grate:
 *   --ports 8080-8090 %{ testing-grate.cwasm -s 49:0,42:0,43:0 %}
 *
 * testing-grate stubs: bind(49)=0, connect(42)=0, accept(43)=0.
 * Clamped port calls should return 0 (from the stub).
 * Unclamped port calls go to the kernel.
 */
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int tests_run = 0;
static int tests_passed = 0;

#define CHECK(name, expr) do { \
    tests_run++; \
    if (expr) { printf("PASS: %s\n", name); tests_passed++; } \
    else { printf("FAIL: %s (errno=%d)\n", name, errno); } \
} while (0)

static struct sockaddr_in make_addr(uint16_t port) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return addr;
}

int main(void) {
    /* Test 1: socket() should work */
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    CHECK("socket()", fd >= 0);
    if (fd >= 0) close(fd);

    /* Test 2: bind to clamped port — routed to testing-grate stub, returns 0 */
    fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = make_addr(8080);
    int ret = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    CHECK("bind to clamped port 8080 returns 0", ret == 0);
    if (fd >= 0) close(fd);

    /* Test 3: bind to unclamped port — passthrough to kernel */
    fd = socket(AF_INET, SOCK_STREAM, 0);
    addr = make_addr(9999);
    ret = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    CHECK("bind to unclamped port 9999 succeeds", ret == 0);
    if (fd >= 0) close(fd);

    /* Test 4: connect to clamped port — routed to testing-grate stub, returns 0 */
    fd = socket(AF_INET, SOCK_STREAM, 0);
    addr = make_addr(8085);
    ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    CHECK("connect to clamped port 8085 returns 0", ret == 0);
    if (fd >= 0) close(fd);

    /* Test 5: connect to unclamped port — passthrough to kernel, fails (no server) */
    fd = socket(AF_INET, SOCK_STREAM, 0);
    addr = make_addr(12345);
    ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    CHECK("connect to unclamped port 12345 fails (no server)", ret < 0);
    if (fd >= 0) close(fd);

    printf("\nResult: %d/%d passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
