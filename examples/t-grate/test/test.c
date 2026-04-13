#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>

int main() {
    printf("[cage] Init...\n");

    char buf[10];
    int ret = read(10, buf, 10); 
    
    printf("[cage] read ret=%d\n", ret);
    exit(0);
}
