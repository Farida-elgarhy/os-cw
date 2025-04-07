#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/sha.h>
#define PORT 8080
#define BUFFER_SIZE 1024

// User credentials 2D array
//const char *userstable[][2] = {
//    {"farida", "farida@!"},
//    {"user", "p@ssword2"},
//    {"admin", "@dmin"}
//};

// function to remove newline
void remove_newline(char *str) {
    for (int i = 0; str[i] != '\0'; i++) {
        if (str[i] == '\n') {
            str[i] = '\0';
            break;
        }
    }
}

// function to Send message and handle error
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

#define SALT_LENGTH 16
#define HASH_LENGTH SHA256_DIGEST_LENGTH

// Convert binary to hex
void to_hex(const unsigned char *in, size_t len, char *out) {
    for (size_t i = 0; i < len; i++) {
        sprintf(out + (i * 2), "%02x", in[i]);
    }
    out[len * 2] = '\0';
}

// Function to hash a password with salt
void hash_password(const char *password, const char *salt, char *hash_out) {
    char salted[512];
    unsigned char hash[HASH_LENGTH];
    
    // Combine salt and password
    sprintf(salted, "%s%s", salt, password);
    
    // Hash the salted password
    SHA256((unsigned char *)salted, strlen(salted), hash);
    
    // Convert hash to hex
    to_hex(hash, HASH_LENGTH, hash_out);
}

// Authentication function
int authenticate(const char username[], const char password[]) {
    FILE *file = fopen("credentials.txt", "r");
    if (file == NULL) return 0;

    char buffer[BUFFER_SIZE] = {0};
    char stored_username[50];
    char stored_salt[33];    // 32 hex chars + null
    char stored_hash[65];    // 64 hex chars + null
    int i;

    while (fgets(buffer, sizeof(buffer), file)) {
        // Get username (copy until space)
        for(i = 0; buffer[i] != ' ' && buffer[i] != '\0'; i++) {
            stored_username[i] = buffer[i];
        }
        stored_username[i] = '\0';
        i++; // skip space

        // Get salt (copy until next space)
        int j;
        for(j = 0; buffer[i] != ' ' && buffer[i] != '\0'; i++, j++) {
            stored_salt[j] = buffer[i];
        }
        stored_salt[j] = '\0';
        i++; // skip space

        // Get hash (copy until newline)
        for(j = 0; buffer[i] != '\n' && buffer[i] != '\0'; i++, j++) {
            stored_hash[j] = buffer[i];
        }
        stored_hash[j] = '\0';


        // If username matches, check password
        if (strcmp(username, stored_username) == 0) {
            printf("Found matching username: %s\n", username);
            char computed_hash[65];
            hash_password(password, stored_salt, computed_hash);
            printf("Input password: %s\n", password);
            printf("Stored  hash: %s\n", stored_hash);
            printf("Computed hash: %s\n", computed_hash);
            
            if (strcmp(computed_hash, stored_hash) == 0) {
                fclose(file);
                return 1;
            }
            break;  // Username found but wrong password
        }
    }
    fclose(file);
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
