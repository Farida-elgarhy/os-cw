#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define PORT 8080
#define BUFFER_SIZE 1024
#define SALT_LENGTH 16
#define HASH_LENGTH SHA256_DIGEST_LENGTH

// User credentials 2D array
//const char *userstable[][2] = {
//    {"farida", "farida@!"},
//    {"user", "p@ssword2"},
//    {"admin", "@dmin"}
//};

// function to remove newline
//void remove_newline(char *str) {
//    for (int i = 0; str[i] != '\0'; i++) {
//        if (str[i] == '\n') {
//            str[i] = '\0';
//            break;
//        }
//    }
//}

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
        // Get username 
        for(i = 0; buffer[i] != ' ' && buffer[i] != '\0'; i++) {
            stored_username[i] = buffer[i];
        }
        stored_username[i] = '\0';
        i++; // skip space

        // Get salt
        int j;
        for(j = 0; buffer[i] != ' ' && buffer[i] != '\0'; i++, j++) {
            stored_salt[j] = buffer[i];
        }
        stored_salt[j] = '\0';
        i++; // skip space

        // Get hash 
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

    //  AES-256  stronger encryption
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

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    unsigned char buffer[BUFFER_SIZE] = {0};
    char username[50], password[50];
    int attempts = 0;
    const int maximum_attempts = 3;
    int encrypted_len;
    unsigned char key[16], iv[16];
    unsigned char ciphertext[128], decrypted_message[128];
    char hex[256];
    
    printf("\n=== Secure Server Started ===\n");

    // Generate random key and IV
    if (!RAND_bytes(key, 16) || !RAND_bytes(iv, 16)) {
        perror("Failed to generate random key/IV");
        exit(EXIT_FAILURE);
    }

    printf("Generated random key and IV\n");
    
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
    printf("Client connected\n");

    // Send the key and IV to client
    if (send(new_socket, key, 16, 0) != 16 || send(new_socket, iv, 16, 0) != 16) {
        perror("Failed to send key/IV");
        close(new_socket);
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    printf("Sent encryption key and IV to client\n");

    //  Authentication loop 
    while (attempts < maximum_attempts) {
        //sends and receives encrypted username 
        int encrypted_len = encrypt((unsigned char *)"Enter username: ", ciphertext, key, iv);
        send_message(new_socket, ciphertext, encrypted_len);
        int received_len = read_message(new_socket, buffer, BUFFER_SIZE, "Read username failed");
        decrypt(buffer, received_len, username, key, iv);        
        printf("Encrypted username received: ");
        strToHex("", buffer, received_len);
        printf("Decrypted username: %s\n", username);

        // send and receive pasxsword
        encrypted_len = encrypt((unsigned char *)"Enter password: ", ciphertext, key, iv);
        send_message(new_socket, ciphertext, encrypted_len);
        received_len = read_message(new_socket, buffer, BUFFER_SIZE, "Read password failed");
        decrypt(buffer, received_len, password, key, iv);
        printf("Encrypted password received: ");
        strToHex("", buffer, received_len);
        printf(" Decrypted password: %s\n", password);

        // Check credentials
        if (authenticate(username, password)) {
            encrypted_len = encrypt((unsigned char *)"Authentication successful", ciphertext, key, iv);
            send_message(new_socket, ciphertext, encrypted_len);
            printf("Sent auth success message (encrypted)\n");

            // Read and decrypt final client message
            received_len = read_message(new_socket, buffer, BUFFER_SIZE, "Read client message");
            decrypt(buffer, received_len, decrypted_message, key, iv);
            printf("Encrypted message: "); strToHex("", buffer, received_len);
            printf("Decrypted message: %s\n", decrypted_message);

            encrypted_len = encrypt((unsigned char *)"Message received", ciphertext, key, iv);
            send_message(new_socket, ciphertext, encrypted_len);
            break;
        } else {
            attempts++;
            if (attempts == maximum_attempts) {
                encrypted_len = encrypt((unsigned char *)"Authentication failed. Too many attempts.", ciphertext, key, iv);
                send_message(new_socket, ciphertext, encrypted_len);
                printf("authentication failed - too many attempts\n");
                close(new_socket);
                close(server_fd);
                return 0;
            } else {
                encrypted_len = encrypt((unsigned char *)"Authentication failed. Try again.", ciphertext, key, iv);
                send_message(new_socket, ciphertext, encrypted_len);
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
