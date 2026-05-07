#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
    fprintf(stderr, "This program will exit with failure status.\n");
    return 77;
}
