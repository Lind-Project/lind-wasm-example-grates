#include <stdio.h>
#include <sys/stat.h>

static int failures = 0;
static int total = 0;

#define CHECK(name, expression)                                              \
    do {                                                                     \
        total++;                                                             \
        if (expression) {                                                    \
            printf("PASS: %s\n", name);                                    \
        } else {                                                             \
            printf("FAIL: %s\n", name);                                    \
            failures++;                                                      \
        }                                                                    \
    } while (0)

int main(void) {
    // The grate is launched with --force-bits 022. Each request is OR'd
    // with 0022, and umask() returns the previous stored effective mask.
    CHECK("initial previous mask", umask(0000) == 0022);
    CHECK("previous enforced mask", umask(0077) == 0022);
    CHECK("previous restrictive mask", umask(0002) == 0077);
    CHECK("forced bits applied", umask(0000) == 0022);

    printf("Result (%d/%d passed).\n", total - failures, total);
    return failures ? 1 : 0;
}
