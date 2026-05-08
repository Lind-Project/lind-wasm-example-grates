// trigger_net_fd_translation.c
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

int main(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }

    printf("socket fd = %d\n", fd);

    ssize_t n = write(fd, "hello\n", 6);
    if (n < 0) {
        printf("write failed: errno=%d (%s)\n", errno, strerror(errno));
    } else {
        printf("write succeeded: %zd\n", n);
    }

    close(fd);
    return 0;
}
