// client.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8080
#define BUFFER_SIZE 1024

// function to Remove newline from fgets input 
void remove_newline(char *str) {
    for (int i = 0; str[i] != '\0'; i++) {
        if (str[i] == '\n') {
            str[i] = '\0';
            break;
        }
    }
}

// function to Read message from server with error handling 
void read_message(int sock, char *buffer, size_t size, const char *error_msg) {
    memset(buffer, 0, size);
    int bytes = read(sock, buffer, size);
    if (bytes <= 0) {
        perror(error_msg);
        close(sock);
        exit(EXIT_FAILURE);
    }
    buffer[bytes] = '\0';
}

// function to Send message to server with error handling 
void send_message(int sock, const char *buffer, const char *error_msg) {
    if (send(sock, buffer, strlen(buffer), 0) < 0) {
        perror(error_msg);
        close(sock);
        exit(EXIT_FAILURE);
    }
}

int main() {
    int sock;
    struct sockaddr_in server_address;
    char buffer[BUFFER_SIZE] = {0};
    char username[50], password[50];

    const char *success_msg = "Authentication successful";
    const char *fail_msg = "Authentication failed. Too many attempts.";

    // step1: Create socket 
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // step2: Set server address 
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(PORT);
    server_address.sin_addr.s_addr = INADDR_ANY; // localhost

    // step3: Connect to server 
    if (connect(sock, (struct sockaddr*)&server_address, sizeof(server_address)) < 0) {
        perror("Connection failed");
        close(sock);
        exit(EXIT_FAILURE);
    }

    //  Authentication loop 
    while (1) {
        // Prompt for username
        read_message(sock, buffer, BUFFER_SIZE, "Failed to receive username");
        printf("%s", buffer);
        fgets(username, sizeof(username), stdin);
        remove_newline(username);
        send_message(sock, username, "Failed to send username");

        // Prompt for password
        read_message(sock, buffer, BUFFER_SIZE, "Failed to receive password ");
        printf("%s", buffer);
        fgets(password, sizeof(password), stdin);
        remove_newline(password);
        send_message(sock, password, "Failed to send password");

        // Receive authentication response
        read_message(sock, buffer, BUFFER_SIZE, "Failed to receive authentication response");
        printf("Server: %s\n", buffer);

        // Check if auth was successful or failed
        if (strncmp(buffer, success_msg, strlen(success_msg)) == 0) {
            break;
        }

        if (strncmp(buffer, fail_msg, strlen(fail_msg)) == 0) {
            close(sock);
            return 0;
        }
    }

    //  Send message to server after successful login 
    printf("Enter message to server: ");
    fgets(buffer, BUFFER_SIZE, stdin);
    remove_newline(buffer);
    send_message(sock, buffer, "Failed to send message");

    //  Receive acknowledgment from server 
    read_message(sock, buffer, BUFFER_SIZE, "Failed to receive acknowledgment");
    printf("Server: %s\n", buffer);

    //close connection
    close(sock);
    return 0;
}
