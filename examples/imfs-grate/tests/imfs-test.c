#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

int main(int argc, char *argv[]) {
        int fd = open("testfile.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
        if (fd < 0) {
                fprintf(stderr, "FAIL: open create\n");
                return 1;
        }

        char wbuf[5] = "Hello";
        int wret = write(fd, wbuf, 5);
        if (wret != 5) {
                fprintf(stderr, "FAIL: write returned %d\n", wret);
                return 1;
        }

        int cret = close(fd);
        if (cret != 0) {
                fprintf(stderr, "FAIL: close after write\n");
                return 1;
        }

        fd = open("testfile.txt", O_RDONLY);
        if (fd < 0) {
                fprintf(stderr, "FAIL: open readonly\n");
                return 1;
        }

        char rbuf[6];
        int rret = read(fd, rbuf, 5);
        if (rret != 5) {
                fprintf(stderr, "FAIL: read returned %d\n", rret);
                return 1;
        }
        rbuf[5] = '\0';

        if (strcmp(rbuf, "Hello") != 0) {
                fprintf(stderr, "FAIL: data mismatch (%s)\n", rbuf);
                return 1;
        }

        cret = close(fd);
        if (cret != 0) {
                fprintf(stderr, "FAIL: close after read\n");
                return 1;
        }

        return 0;
}

