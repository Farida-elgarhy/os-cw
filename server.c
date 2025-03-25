#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8080
#define BUFFER_SIZE 1024

// User credentials 2D array
const char *userstable[][2] = {
    {"farida", "farida@!"},
    {"user", "p@ssword2"},
    {"admin", "@dmin"}
};

// function to remove newline
void remove_newline(char *str) {
    for (int i = 0; str[i] != '\0'; i++) {
        if (str[i] == '\n') {
            str[i] = '\0';
            break;
        }
    }
}

// fucntion to Send message and handle error
void send_message(int socket, const char *msg) {
    if (send(socket, msg, strlen(msg), 0) < 0) {
        perror("Send failed");
        close(socket);
        exit(EXIT_FAILURE);
    }
}

// function to Read message and handle error
void read_message(int socket, char *buffer, size_t size, const char *error_msg) {
    memset(buffer, 0, size);
    int bytes = read(socket, buffer, size);
    if (bytes <= 0) {
        perror(error_msg);
        close(socket);
        exit(EXIT_FAILURE);
    }
    remove_newline(buffer);
}

// Authentication function
int authenticate(const char username[], const char password[]) {
    int total_users = sizeof(userstable) / sizeof(userstable[0]);
    for (int i = 0; i < total_users; i++) {
        if (strcmp(username, userstable[i][0]) == 0 &&
            strcmp(password, userstable[i][1]) == 0) {
            return 1;
        }
    }
    return 0;
}

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    char buffer[BUFFER_SIZE] = {0};
    char username[50], password[50];
    int attempts = 0;
    const int maximum_attempts = 3;

    // step1: Create socket 
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }
    //step2: configure server address
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // step3: Bind socket
    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // step4: Listen for connections
    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }


    printf("Server listening on port %d...\n", PORT);
    
    //step5:accept connection
    if ((new_socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen)) < 0) {
        perror("Accept failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    //  Authentication loop 
    while (attempts < maximum_attempts) {
        //sends and receives username
        send_message(new_socket, "Enter username: ");
        read_message(new_socket, username, sizeof(username), "Read username failed");
        printf("Username received: %s\n", username);

        // send and receive password
        send_message(new_socket, "Enter password: ");
        read_message(new_socket, password, sizeof(password), "Read password failed");
        printf("Password received: %s\n", password);

        // Check credentials
        if (authenticate(username, password)) {
            send_message(new_socket, "Authentication successful");
            printf("authentication successful\n");

            // Receive and respond to client message
            read_message(new_socket, buffer, BUFFER_SIZE, "Failed to read message");
            printf("Client message: %s\n", buffer);
            send_message(new_socket, "Message received");
            break;
        } else {
            attempts++;
            if (attempts == maximum_attempts) {
                send_message(new_socket, "Authentication failed. Too many attempts.");
                printf("authentication failed - too many attempts\n");
                close(new_socket);
                close(server_fd);
                return 0;
            } else {
                send_message(new_socket, "Authentication failed. Try again.");
                sleep(1); // Prevent message merge
                printf("authentication failed - attempt %d\n", attempts);
            }
        }
    }

    //step8: close connection
    close(new_socket);
    close(server_fd);
    return 0;
}
