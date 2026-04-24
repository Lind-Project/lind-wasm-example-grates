#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define PORT 8081
#define BUFFER_SIZE 1024

int main() {
    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[BUFFER_SIZE] = {0};
    const char *hello = "Hello from the Lind mTLS Client!";

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error \n");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        printf("\nInvalid address\n");
        return -1;
    }

    printf("[Client] Attempting to connect...\n");
    // Grate intercepts this and performs the mTLS Handshake using client.crt
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("\nConnection Failed \n");
        return -1;
    }

    // Send encrypted payload
    write(sock, hello, strlen(hello));
    printf("[Client] Encrypted message sent.\n");

    // Read the server's encrypted response
    int valread = read(sock, buffer, BUFFER_SIZE - 1);
    if (valread > 0) {
        printf("[Client] Decrypted response: %s", buffer);
    }

    close(sock);
    return 0;
}
