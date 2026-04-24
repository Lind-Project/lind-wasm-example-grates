#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/wait.h>

#define PORT 443
#define BUFFER_SIZE 1024

void handle_client(int client_fd) {
    char buffer[BUFFER_SIZE] = {0};
    const char *response = "Hello from the Lind mTLS Server!\n";

    // Edge Case: Duplicate the file descriptor to prove fdtables session mapping
    int dup_fd = dup(client_fd);
    if (dup_fd < 0) {
        perror("[Server] dup failed");
        exit(EXIT_FAILURE);
    }
    close(client_fd); // Close original, rely on dup

    // Read the incoming client message
    int valread = read(dup_fd, buffer, BUFFER_SIZE - 1);
    if (valread > 0) {
        printf("[Server Child] Decrypted %d bytes: %s\n", valread, buffer);
    } else {
        printf("[Server Child] Read failed or connection closed.\n");
    }

    // Send the encrypted response
    write(dup_fd, response, strlen(response));
    printf("[Server Child] Encrypted response sent.\n");

    // Clean teardown triggers TLS close_notify
    close(dup_fd);
}

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed"); exit(EXIT_FAILURE);
    }

    // Allow port reuse for rapid testing
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed"); exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0) {
        perror("listen"); exit(EXIT_FAILURE);
    }
    
    printf("[Server] Listening on port %d (Waiting for mTLS connection...)\n", PORT);

    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
        perror("accept"); exit(EXIT_FAILURE);
    }
    printf("[Server] Connection accepted! Forking...\n");

    // Edge Case: Forking tests SYS_CLONE state preservation
    pid_t pid = fork();
    if (pid == 0) {
        close(server_fd); 
        handle_client(new_socket);
        exit(EXIT_SUCCESS);
    } else if (pid > 0) {
        close(new_socket); 
        wait(NULL); 
        printf("[Server] Parent shutting down.\n");
        close(server_fd);
    } else {
        perror("fork failed");
    }

    return 0;
}
