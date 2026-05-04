/* pipe_stdin_reader.c — Helper binary for popen/exec pipe tests.
 *
 * Reads all data from stdin, verifies it matches expected pattern,
 * exits 0 on success, 1 on mismatch, 2 on read error.
 *
 * Expected pattern: repeating 'A' + (offset % 26) for the number of
 * bytes specified as argv[1].
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: pipe_stdin_reader <expected_bytes>\n");
        return 2;
    }

    long expected = atol(argv[1]);
    if (expected <= 0 || expected > 4 * 1024 * 1024) {
        fprintf(stderr, "Invalid byte count: %s\n", argv[1]);
        return 2;
    }

    char *buf = malloc(expected);
    if (!buf) {
        fprintf(stderr, "malloc failed\n");
        return 2;
    }

    long total = 0;
    while (total < expected) {
        ssize_t n = read(STDIN_FILENO, buf + total, expected - total);
        if (n < 0) {
            fprintf(stderr, "read error at offset %ld\n", total);
            free(buf);
            return 2;
        }
        if (n == 0) break; /* EOF */
        total += n;
    }

    if (total != expected) {
        fprintf(stderr, "short read: got %ld, expected %ld\n", total, expected);
        free(buf);
        return 1;
    }

    /* Verify pattern */
    for (long i = 0; i < expected; i++) {
        char want = 'A' + (i % 26);
        if (buf[i] != want) {
            fprintf(stderr, "mismatch at offset %ld: got 0x%02x, want 0x%02x\n",
                    i, (unsigned char)buf[i], (unsigned char)want);
            free(buf);
            return 1;
        }
    }

    free(buf);
    return 0;
}
