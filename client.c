#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

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
int read_message(int sock, unsigned char *buffer, size_t size, const char *error_msg) {
    memset(buffer, 0, size);
    int bytes = read(sock, buffer, size);
    if (bytes <= 0) {
        perror(error_msg);
        close(sock);
        exit(EXIT_FAILURE);
    }
    return bytes;
}

// function to Send message to server with error handling 
void send_message(int sock, unsigned char *data, int len, const char *error_msg) {
    if (send(sock, data, len, 0) < 0) {
        perror(error_msg);
        close(sock);
        exit(EXIT_FAILURE);
    }
}

// Encrypts plaintext 
int encrypt(unsigned char *plaintext, unsigned char *ciphertext,
            unsigned char *key, unsigned char *iv) {
    EVP_CIPHER_CTX *encryption_context = EVP_CIPHER_CTX_new();
    int bytes_written = 0;
    int final_bytes = 0;

    // Use AES-256 
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

    // Use AES-256 
    EVP_DecryptInit_ex(decryption_context, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_DecryptUpdate(decryption_context, plaintext, &bytes_written, ciphertext, ciphertext_len);
    EVP_DecryptFinal_ex(decryption_context, plaintext + bytes_written, &final_bytes);
    plaintext[bytes_written + final_bytes] = '\0';

    EVP_CIPHER_CTX_free(decryption_context);
    return bytes_written + final_bytes;
}

void strToHex(const char *label, unsigned char *data, int len) {
    printf("%s: ", label);
    for (int i = 0; i < len; i++) printf("%02X", data[i]);
    printf("\n");
}

int main() {
    int sock;
    struct sockaddr_in server_address;
    char username[50], password[50];
    unsigned char key[16], iv[16];
    unsigned char buffer[BUFFER_SIZE] = {0}, ciphertext[BUFFER_SIZE], decrypted_message[BUFFER_SIZE];
    char hex[256];
    int encrypted_len;

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

    printf("\n=== Secure Client Started ===\n\n");

    // Receive the key and IV from server
    if (read(sock, key, 16) != 16 || read(sock, iv, 16) != 16) {
        perror("Failed to receive key/IV");
        close(sock);
        exit(EXIT_FAILURE);
    }
    printf("Received encryption key and IV from server\n");

    //  Authentication loop 
    while (1) {
        // Username prompt
        int encrypted_len = read_message(sock, buffer, BUFFER_SIZE, "Failed to receive username");
        printf("\nEncrypted: ");
        strToHex("", buffer, encrypted_len);
        printf("Decrypted: ");
        decrypt(buffer, encrypted_len, decrypted_message, key, iv);
        printf("%s", decrypted_message);
        
        // Send username
        fgets((char *)username, sizeof(username), stdin);
        remove_newline((char *)username);
        encrypted_len = encrypt(username, ciphertext, key, iv);
        send_message(sock, ciphertext, encrypted_len, "Failed to send username");

        // Password prompt
        encrypted_len = read_message(sock, buffer, BUFFER_SIZE, "Failed to receive password");
        printf("\nEncrypted: ");
        strToHex("", buffer, encrypted_len);
        printf("Decrypted: ");
        decrypt(buffer, encrypted_len, decrypted_message, key, iv);
        printf("%s", decrypted_message);
        
        // Send password
        fgets((char *)password, sizeof(password), stdin);
        remove_newline((char *)password);
        encrypted_len = encrypt(password, ciphertext, key, iv);
        send_message(sock, ciphertext, encrypted_len, "Failed to send password");

        // Authentication response
        encrypted_len = read_message(sock, buffer, BUFFER_SIZE, "Failed to receive auth response");
        printf("\nEncrypted: ");
        strToHex("", buffer, encrypted_len);
        printf("Decrypted: ");
        decrypt(buffer, encrypted_len, decrypted_message, key, iv);
        printf("%s\n", decrypted_message);

        // Check if auth was successful or failed
        if (strncmp((char *)decrypted_message, success_msg, strlen(success_msg)) == 0) {
            break;
        }

        if (strncmp((char *)decrypted_message, fail_msg, strlen(fail_msg)) == 0) {
            close(sock);
            return 0;
        }
    }

    //  Send message to server after successful login 
    printf("Enter message to server: ");
    fgets((char *)buffer, BUFFER_SIZE, stdin);
    remove_newline((char *)buffer);
    encrypted_len = encrypt(buffer, ciphertext, key, iv);
    send_message(sock, ciphertext, encrypted_len, "Failed to send message");

    //  Receive acknowledgment from server 
    encrypted_len = read_message(sock, buffer, BUFFER_SIZE, "Failed to receive acknowledgment");
    decrypt(buffer, encrypted_len, decrypted_message, key, iv);
    printf("Encrypted server response: ");
    strToHex("", buffer, encrypted_len);
    printf("Server: %s\n", decrypted_message);

    //close connection
    close(sock);
    return 0;
}
