/*
 * Rate-limit clamping demo.
 *
 * net-routing-clamp routes port 5432 through resource-grate (rate limiter).
 * File I/O is unaffected because it doesn't go through the clamped grate.
 *
 * Usage:
 *   lind-wasm grates/net-routing-clamp.cwasm --ports 5432-5432 %{ \
 *     grates/resource-grate.cwasm ratelimit_demo.cfg \
 *   %} ratelimit_demo.cwasm
 */
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define WRITE_SIZE 4096
#define NUM_WRITES 50
#define TOTAL_BYTES (WRITE_SIZE * NUM_WRITES)

static double elapsed_sec(struct timespec *start, struct timespec *end) {
    return (end->tv_sec - start->tv_sec)
         + (end->tv_nsec - start->tv_nsec) / 1e9;
}

static double file_throughput = 0;
static double socket_throughput = 0;

static void test_file_write(void) {
    printf("=== File I/O (no rate limit) ===\n");

    int fd = open("/tmp/ratelimit_demo.tmp", O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) {
        printf("  SKIP: open failed (errno=%d)\n", errno);
        return;
    }

    char buf[WRITE_SIZE];
    memset(buf, 'F', sizeof(buf));

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    for (int i = 0; i < NUM_WRITES; i++) {
        if (write(fd, buf, sizeof(buf)) != sizeof(buf)) {
            printf("  write failed at i=%d (errno=%d)\n", i, errno);
            break;
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    double dt = elapsed_sec(&start, &end);
    file_throughput = (TOTAL_BYTES / 1024.0) / dt;

    close(fd);
    unlink("/tmp/ratelimit_demo.tmp");

    printf("  Wrote %d bytes in %.3fs (%.0f KB/s)\n", TOTAL_BYTES, dt, file_throughput);
}

static void test_socket_write(void) {
    printf("\n=== Socket write to port 5432 (rate-limited) ===\n");

    int server = socket(AF_INET, SOCK_STREAM, 0);
    if (server < 0) {
        printf("  SKIP: socket failed (errno=%d)\n", errno);
        return;
    }

    int optval = 1;
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(5432);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(server, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        printf("  SKIP: bind failed (errno=%d)\n", errno);
        close(server);
        return;
    }

    if (listen(server, 1) < 0) {
        printf("  SKIP: listen failed (errno=%d)\n", errno);
        close(server);
        return;
    }

    pid_t pid = fork();
    if (pid < 0) {
        printf("  SKIP: fork failed\n");
        close(server);
        return;
    }

    if (pid == 0) {
        close(server);

        int client = socket(AF_INET, SOCK_STREAM, 0);
        if (connect(client, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            _exit(1);
        }

        char buf[WRITE_SIZE];
        memset(buf, 'N', sizeof(buf));

        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);

        for (int i = 0; i < NUM_WRITES; i++) {
            ssize_t n = write(client, buf, sizeof(buf));
            if (n <= 0) break;
        }

        clock_gettime(CLOCK_MONOTONIC, &end);
        double dt = elapsed_sec(&start, &end);
        double tp = (TOTAL_BYTES / 1024.0) / dt;

        printf("  Wrote %d bytes in %.3fs (%.0f KB/s)\n", TOTAL_BYTES, dt, tp);

        /* Write throughput to a temp file so parent can read it */
        int tfd = open("/tmp/ratelimit_tp.tmp", O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (tfd >= 0) {
            char tbuf[32];
            int tlen = snprintf(tbuf, sizeof(tbuf), "%.2f", tp);
            write(tfd, tbuf, tlen);
            close(tfd);
        }

        close(client);
        _exit(0);
    }

    int conn = accept(server, NULL, NULL);
    if (conn >= 0) {
        char drain[8192];
        while (read(conn, drain, sizeof(drain)) > 0) {}
        close(conn);
    }

    int status;
    waitpid(pid, &status, 0);
    close(server);

    /* Read child's throughput */
    int tfd = open("/tmp/ratelimit_tp.tmp", O_RDONLY);
    if (tfd >= 0) {
        char tbuf[32] = {0};
        read(tfd, tbuf, sizeof(tbuf) - 1);
        close(tfd);
        unlink("/tmp/ratelimit_tp.tmp");
        sscanf(tbuf, "%lf", &socket_throughput);
    }
}

int main(void) {
    test_file_write();
    test_socket_write();

    printf("\n=== Results ===\n");
    printf("  File I/O:     %.0f KB/s\n", file_throughput);
    printf("  Socket (5432): %.0f KB/s\n", socket_throughput);

    if (file_throughput > 0 && socket_throughput > 0) {
        double ratio = file_throughput / socket_throughput;
        double reduction = (1.0 - socket_throughput / file_throughput) * 100.0;
        printf("  Slowdown:      %.1fx slower\n", ratio);
        printf("  Reduction:     %.1f%%\n", reduction);

        if (reduction > 50.0) {
            printf("  PASS: socket writes significantly throttled\n");
        } else if (reduction > 10.0) {
            printf("  PASS: socket writes measurably throttled\n");
        } else {
            printf("  FAIL: socket writes not throttled (rate limiting not working)\n");
        }
    }

    return 0;
}
