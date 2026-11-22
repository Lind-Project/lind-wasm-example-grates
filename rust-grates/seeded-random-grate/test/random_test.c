// Test for the seeded-random grate. The grate answers getrandom with the ChaCha20 stream of
// (RANDOM_GRATE_SEED, cage id, position in that cage's stream); this program computes the same
// stream and compares. Run twice, it prints the same lines.
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/wait.h>
#include <unistd.h>

static int failures = 0;

#define CHECK(name, expr) \
    do { if (expr) printf("PASS: %s\n", name); else { printf("FAIL: %s\n", name); failures++; } } while (0)

static uint32_t rotl(uint32_t v, int n) { return (v << n) | (v >> (32 - n)); }

#define QUARTER(a, b, c, d) \
    do { \
        s[a] += s[b]; s[d] = rotl(s[d] ^ s[a], 16); \
        s[c] += s[d]; s[b] = rotl(s[b] ^ s[c], 12); \
        s[a] += s[b]; s[d] = rotl(s[d] ^ s[a], 8); \
        s[c] += s[d]; s[b] = rotl(s[b] ^ s[c], 7); \
    } while (0)

// One ChaCha20 block: 64-bit counter, 64-bit nonce.
static void block(const uint8_t key[32], uint64_t counter, uint64_t nonce, uint8_t out[64]) {
    uint32_t init[16] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};
    uint32_t s[16];
    for (int i = 0; i < 8; i++)
        init[4 + i] = key[4 * i] | key[4 * i + 1] << 8 | key[4 * i + 2] << 16 | (uint32_t)key[4 * i + 3] << 24;
    init[12] = (uint32_t)counter;
    init[13] = (uint32_t)(counter >> 32);
    init[14] = (uint32_t)nonce;
    init[15] = (uint32_t)(nonce >> 32);
    memcpy(s, init, sizeof s);
    for (int i = 0; i < 10; i++) {
        QUARTER(0, 4, 8, 12); QUARTER(1, 5, 9, 13); QUARTER(2, 6, 10, 14); QUARTER(3, 7, 11, 15);
        QUARTER(0, 5, 10, 15); QUARTER(1, 6, 11, 12); QUARTER(2, 7, 8, 13); QUARTER(3, 4, 9, 14);
    }
    for (int i = 0; i < 16; i++) {
        uint32_t v = s[i] + init[i];
        out[4 * i] = v; out[4 * i + 1] = v >> 8; out[4 * i + 2] = v >> 16; out[4 * i + 3] = v >> 24;
    }
}

// The bytes at pos..pos+len of the stream of `cage` under `seed`.
static void expected(uint64_t seed, uint64_t cage, uint64_t pos, uint8_t *out, size_t len) {
    uint8_t key[32], b[64];
    for (int i = 0; i < 8; i++) key[i] = seed >> (8 * i);
    memcpy(key + 8, "seeded-random-grate v1\0\0", 24);
    for (size_t done = 0; done < len; done++, pos++) {
        if (done == 0 || pos % 64 == 0) block(key, pos / 64, cage, b);
        out[done] = b[pos % 64];
    }
}

static int at(uint64_t seed, uint64_t cage, uint64_t pos, const uint8_t *got, size_t len) {
    uint8_t *want = malloc(len);
    expected(seed, cage, pos, want, len);
    int same = memcmp(got, want, len) == 0;
    free(want);
    return same;
}

static void hex(const char *label, const uint8_t *b, size_t len) {
    printf("%s", label);
    for (size_t i = 0; i < len; i++) printf("%02x", b[i]);
    printf("\n");
}

int main(void) {
    const char *env = getenv("RANDOM_GRATE_SEED");
    uint64_t seed = env ? strtoull(env, NULL, 10) : 0;
    uint64_t cage = getpid();
    uint8_t a[16], b[16];
    static uint8_t big[10000];

    // libc may have read from the stream before main, so the first read here can be some way into
    // it: find where.
    CHECK("getrandom returns the length asked for", getrandom(a, sizeof a, 0) == sizeof a);
    long pos = -1;
    for (long p = 0; p < 4096 && pos < 0; p++)
        if (at(seed, cage, p, a, sizeof a)) pos = p;
    CHECK("the bytes are on this cage's stream", pos >= 0);
    printf("cage %llu, seed %llu, %ld bytes read before main\n",
           (unsigned long long)cage, (unsigned long long)seed, pos);
    hex("first bytes: ", a, sizeof a);
    if (pos < 0) return 1;
    pos += sizeof a;

    CHECK("the next read continues the stream",
          getrandom(b, sizeof b, GRND_NONBLOCK) == sizeof b && at(seed, cage, pos, b, sizeof b));
    pos += sizeof b;

    CHECK("a read longer than a block and a chunk",
          getrandom(big, sizeof big, GRND_RANDOM) == sizeof big && at(seed, cage, pos, big, sizeof big));
    pos += sizeof big;

    errno = 0;
    CHECK("an unknown flag is EINVAL", getrandom(b, sizeof b, 0x100) == -1 && errno == EINVAL);
    errno = 0;
    CHECK("GRND_RANDOM with GRND_INSECURE is EINVAL", getrandom(b, sizeof b, 2 | 4) == -1 && errno == EINVAL);
    CHECK("a read of nothing returns 0", getrandom(b, 0, 0) == 0);

    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        // A forked cage starts its own stream at 0: it never repeats its parent's bytes.
        uint8_t c[16];
        int ok = getrandom(c, sizeof c, 0) == sizeof c && at(seed, getpid(), 0, c, sizeof c) &&
                 memcmp(c, a, sizeof a) != 0;
        _exit(ok ? 0 : 1);
    }
    int status = -1;
    CHECK("fork", child > 0 && waitpid(child, &status, 0) == child);
    CHECK("the child reads its own stream from the start", WIFEXITED(status) && WEXITSTATUS(status) == 0);

    CHECK("the refused reads and the child did not move this cage's stream",
          getrandom(b, sizeof b, 0) == sizeof b && at(seed, cage, pos, b, sizeof b));

    // arc4random is libc's own consumer of getrandom.
    printf("arc4random: %08x\n", (unsigned)arc4random());

    printf("%s\n", failures ? "random_test FAILED" : "random_test passed");
    return failures ? 1 : 0;
}
