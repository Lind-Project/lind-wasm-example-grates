#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    char *a = malloc(1024), *b = malloc(1024), *c = malloc(1024);
    memset(a, 'A', 1023); a[1023] = '\0';
    memset(b, 'B', 1023); b[1023] = '\0';
    memset(c, 'C', 1023); c[1023] = '\0';

    printf("%s\n%s\n%s\n", a, b, c);

    pid_t pid = fork();
    if (pid == 0) _exit(0);
    printf("%s\n%s\n%s\n", a, b, c);

    pid = fork();
    if (pid == 0) _exit(0);
    printf("%s\n%s\n%s\n", a, b, c);

    return 0;
}
