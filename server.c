#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <pthread.h>

#define PORT 8080
#define BUFFER_SIZE 1024
#define SALT_LENGTH 16
#define HASH_LENGTH SHA256_DIGEST_LENGTH

// function to Send message and handle error
void send_message(int socket, unsigned char *data, int len) {
    if (send(socket, data, len, 0) < 0) {
        perror("Send failed");
        close(socket);
        exit(EXIT_FAILURE);
    }
}

// function to Read message and handle error
int read_message(int socket, unsigned char *buffer, size_t size, const char *error_msg) {
    memset(buffer, 0, size);
    int bytes = read(socket, buffer, size);
    if (bytes <= 0) {
        perror(error_msg);
        close(socket);
        exit(EXIT_FAILURE);
    }
    return bytes;
}



// Convert binary to hex string for storage (used in password hashing)
void convert_to_hex(const unsigned char *in, size_t len, char *out) {
    for (size_t i = 0; i < len; i++) {
        sprintf(out + (i * 2), "%02x", in[i]);
    }
    out[len * 2] = '\0';
}

// Print hex values for display purposes (used for showing encrypted data)
void strToHex(const char *label, unsigned char *data, int len) {
    printf("%s: ", label);
    for (int i = 0; i < len; i++) printf("%02X", data[i]);
    printf("\n");
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
    convert_to_hex(hash, HASH_LENGTH, hash_out);
}

// Authentication function
int authenticate(const char username[], const char password[]) {
    FILE *file = fopen("credentials.txt", "r"); // r is for read
    if (file == NULL) return 0;

    char buffer[BUFFER_SIZE] = {0};
    char stored_username[50];
    char stored_salt[33];    // 32 hex chars + null
    char stored_hash[65];    // 64 hex chars + null
    char computed_hash[65];
    
    while (fgets(buffer, sizeof(buffer), file)) {
        int i;
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

// Encrypts plaintext 
int encrypt(unsigned char *plaintext, unsigned char *ciphertext,
            unsigned char *key, unsigned char *iv) {
    EVP_CIPHER_CTX *encryption_context = EVP_CIPHER_CTX_new();
    int bytes_written = 0;
    int final_bytes = 0;

    // Use AES-256 instead of AES-128 for stronger encryption
    EVP_EncryptInit_ex(encryption_context, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(encryption_context, ciphertext, &bytes_written, plaintext, strlen((char *)plaintext));
    EVP_EncryptFinal_ex(encryption_context, ciphertext + bytes_written, &final_bytes);

    EVP_CIPHER_CTX_free(encryption_context);
    return bytes_written + final_bytes;
}

// Decrypts ciphertext 
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext,
            unsigned char *key, unsigned char *iv) {
    EVP_CIPHER_CTX *decryption_context = EVP_CIPHER_CTX_new();
    int bytes_written = 0;
    int final_bytes = 0;

    // Use AES-256 to match encryption
    EVP_DecryptInit_ex(decryption_context, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_DecryptUpdate(decryption_context, plaintext, &bytes_written, ciphertext, ciphertext_len);
    EVP_DecryptFinal_ex(decryption_context, plaintext + bytes_written, &final_bytes);
    plaintext[bytes_written + final_bytes] = '\0';

    EVP_CIPHER_CTX_free(decryption_context);
    return bytes_written + final_bytes;
}

// Thread function to handle client connection
void* handle_client(void* arg) {
    int client_socket = *(int*)arg;
    unsigned char buffer[BUFFER_SIZE] = {0};
    char username[50], password[50];
    int attempts = 0;
    const int maximum_attempts = 3;
    char hex[256];
    unsigned char key[16], iv[16];
    unsigned char ciphertext[128], decrypted_message[128];
    
    // Generate random key and IV for this client
    if (!RAND_bytes(key, 16) || !RAND_bytes(iv, 16)) {
        perror("Failed to generate random key/IV");
        close(client_socket);
        free(arg);
        return NULL;
    }

    // Send the key and IV to client
    if (send(client_socket, key, 16, 0) != 16 || send(client_socket, iv, 16, 0) != 16) {
        perror("Failed to send key/IV");
        close(client_socket);
        free(arg);
        return NULL;
    }

    // Authentication loop
    while (attempts < maximum_attempts) {
        // Send and receive encrypted username
        int encrypted_len = encrypt((unsigned char *)"Enter username: ", ciphertext, key, iv);
        send_message(client_socket, ciphertext, encrypted_len);
        int received_len = read_message(client_socket, buffer, BUFFER_SIZE, "Read username failed");
        decrypt(buffer, received_len, username, key, iv);
        printf("Client %d - Username received: %s\n", client_socket, username);

        // Send and receive encrypted password
        encrypted_len = encrypt((unsigned char *)"Enter password: ", ciphertext, key, iv);
        send_message(client_socket, ciphertext, encrypted_len);
        received_len = read_message(client_socket, buffer, BUFFER_SIZE, "Read password failed");
        decrypt(buffer, received_len, password, key, iv);
        printf("Client %d - Password received\n", client_socket);

        if (authenticate(username, password)) {
            encrypted_len = encrypt((unsigned char *)"Authentication successful", ciphertext, key, iv);
            send_message(client_socket, ciphertext, encrypted_len);
            printf("Client %d authenticated successfully\n", client_socket);

            // Read and decrypt final client message
            received_len = read_message(client_socket, buffer, BUFFER_SIZE, "Read client message");
            decrypt(buffer, received_len, decrypted_message, key, iv);
            printf("Client %d message: %s\n", client_socket, decrypted_message);

            encrypted_len = encrypt((unsigned char *)"Message received", ciphertext, key, iv);
            send_message(client_socket, ciphertext, encrypted_len);
            break;
        } else {
            attempts++;
            if (attempts == maximum_attempts) {
                encrypted_len = encrypt((unsigned char *)"Authentication failed. Too many attempts.", ciphertext, key, iv);
                send_message(client_socket, ciphertext, encrypted_len);
                printf("Client %d: Authentication failed - max attempts\n", client_socket);
            } else {
                encrypted_len = encrypt((unsigned char *)"Authentication failed. Try again.", ciphertext, key, iv);
                send_message(client_socket, ciphertext, encrypted_len);
                printf("Client %d: Authentication failed - attempt %d\n", client_socket, attempts);
                sleep(1);
            }
        }
    }

    close(client_socket);
    free(arg);
    return NULL;
}

int main() {
    int server_fd;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    printf("\n=== Secure Server Started ===\n");

    // Create socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    // Configure server address
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Bind socket to address
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // Start listening
    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d...\n", PORT);

    while(1) {
        printf("\nWaiting for connection...\n");

        // Accept client
        int* new_socket = malloc(sizeof(int));
        if ((*new_socket = accept(server_fd, (struct sockaddr *)&address, 
                                (socklen_t*)&addrlen)) < 0) {
            perror("Accept failed");
            free(new_socket);
            continue;
        }
        printf("New client connected\n");

        // Create thread for this client
        pthread_t thread;
        if (pthread_create(&thread, NULL, handle_client, new_socket) != 0) {
            perror("Thread creation failed");
            free(new_socket);
            close(*new_socket);
            continue;
        }
    }

    close(server_fd);
    return 0;
}
