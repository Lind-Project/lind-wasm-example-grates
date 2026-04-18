/* Trigger the handler by writing to a file (fd > 2) */
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
    int fd = open("/tmp/memtest.txt", O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) { perror("open"); return 1; }
    write(fd, "trigger\n", 8);
    close(fd);
    unlink("/tmp/memtest.txt");
    return 0;
}
