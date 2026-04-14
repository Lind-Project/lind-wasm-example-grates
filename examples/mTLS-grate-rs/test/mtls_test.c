#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define PORT 443
#define BUFFER_SIZE 1024

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[BUFFER_SIZE] = {0};
    const char *hello = "Hello from the Lind-Wasm Cage!\n";

    // Create socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Bind to port 433
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    // Listen for incoming connections
    if (listen(server_fd, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    
    printf("[App] Listening on port %d (Waiting for connection...)\n", PORT);

    // Accept a connection (This is where the Grate intercepts and does mTLS!)
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
        perror("accept");
        exit(EXIT_FAILURE);
    }
    
    printf("[App] Connection accepted! Waiting for data...\n");

    // Read data (Grate decrypts this)
    int valread = read(new_socket, buffer, BUFFER_SIZE);
    printf("[App] Received %d bytes: %s\n", valread, buffer);

    // Send response (Grate encrypts this)
    write(new_socket, hello, strlen(hello));
    printf("[App] Response message sent\n");

    // Cleanup
    close(new_socket);
    close(server_fd);
    
    return 0;
}
