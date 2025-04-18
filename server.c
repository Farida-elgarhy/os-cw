#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define PORT 8080
#define BUFFER_SIZE 1024
#define HASH_LENGTH 32
#define MAX_CLIENTS 10

int client_counter = 0;
pthread_mutex_t counter_lock;
//pthread_mutex_t log_lock;

void send_message(int socket, unsigned char *data, int len) {
    uint32_t net_len = htonl(len);
    send(socket, &net_len, sizeof(net_len), 0);
    if (send(socket, data, len, 0) < 0) {
        perror("Send failed");
        exit(EXIT_FAILURE);
    }
}

int read_message(int socket, unsigned char *buffer, const char *error_msg) {
    uint32_t net_len;
    if (recv(socket, &net_len, sizeof(net_len), MSG_WAITALL) <= 0) {
        perror("Read length failed");
        exit(EXIT_FAILURE);
    }
    int len = ntohl(net_len);
    if (recv(socket, buffer, len, MSG_WAITALL) <= 0) {
        perror(error_msg);
        exit(EXIT_FAILURE);
    }
    return len;
}

void convert_to_hex(const unsigned char *in, size_t len, char *out) {
    for (size_t i = 0; i < len; i++) {
        sprintf(out + (i * 2), "%02x", in[i]);
    }
    out[len * 2] = '\0';
}

void print_hex(const char *label, unsigned char *data, int len) {
    printf("%s: ", label);
    for (int i = 0; i < len; i++) printf("%02X", data[i]);
    printf("\n");
}

int authenticate(const char username[], const char password[]) {
    FILE *file = fopen("credentials.txt", "r");
    if (!file) return 0;

    char line[BUFFER_SIZE], stored_user[50], stored_salt[33], stored_hash[65], computed_hash[65];

    while (fgets(line, sizeof(line), file)) {
        sscanf(line, "%s %s %s", stored_user, stored_salt, stored_hash);
        if (strcmp(username, stored_user) == 0) {
            char salted[512];
            unsigned char hash[HASH_LENGTH];
            sprintf(salted, "%s%s", stored_salt, password);
            SHA256((unsigned char *)salted, strlen(salted), hash);
            convert_to_hex(hash, HASH_LENGTH, computed_hash);
            fclose(file);
            return strcmp(computed_hash, stored_hash) == 0;
        }
    }

    fclose(file);
    return 0;
}

int encrypt_gcm(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv,
                unsigned char *ciphertext, unsigned char *auth_tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int enc_len, final_len;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);

    EVP_EncryptUpdate(ctx, ciphertext, &enc_len, plaintext, plaintext_len);
    EVP_EncryptFinal_ex(ctx, ciphertext + enc_len, &final_len);
    enc_len += final_len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, auth_tag);
    EVP_CIPHER_CTX_free(ctx);
    return enc_len;
}

int decrypt_gcm(unsigned char *enc_buf, int enc_len,
                unsigned char *auth_tag, unsigned char *key, unsigned char *iv,
                unsigned char *dec_buf) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0, total_len = 0;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);

    EVP_DecryptUpdate(ctx, dec_buf, &len, enc_buf, enc_len);
    total_len = len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, auth_tag);

    if (EVP_DecryptFinal_ex(ctx, dec_buf + len, &len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    total_len += len;
    dec_buf[total_len] = '\0';
    EVP_CIPHER_CTX_free(ctx);
    return total_len;
}

void *handle_client(void *arg) {
    int client_fd = *(int *)arg;
    free(arg);
    //pthread_mutex_lock(&log_lock);
    int client_id;
    pthread_mutex_lock(&counter_lock);
    client_id = ++client_counter;
    pthread_mutex_unlock(&counter_lock);

    unsigned char key[32], iv[12], tag[16];
    unsigned char buffer[BUFFER_SIZE], dec_buf[BUFFER_SIZE];
    char username[50], password[50];
    int attempts = 0;
    const int maximum_attempts = 3;

    printf("\n\n======= New client connected: Client #%d =======\n\n", client_id);

    RAND_bytes(key, sizeof(key));
    RAND_bytes(iv, sizeof(iv));

    send(client_fd, key, 32, 0);
    send(client_fd, iv, 12, 0);

    while (attempts < maximum_attempts) {
        int len = encrypt_gcm((unsigned char *)"Enter username: ", 16, key, iv, buffer, tag);
        send_message(client_fd, buffer, len);
        send_message(client_fd, tag, 16);

        len = read_message(client_fd, buffer, "received username");
        read_message(client_fd, tag, "received tag");
        print_hex("Client's Encrypted Username", buffer, len);
        decrypt_gcm(buffer, len, tag, key, iv, (unsigned char *)username);
        printf("Client's Decrypted Username: %s\n", username);

        len = encrypt_gcm((unsigned char *)"Enter password: ", 16, key, iv, buffer, tag);
        send_message(client_fd, buffer, len);
        send_message(client_fd, tag, 16);

        len = read_message(client_fd, buffer, "received password");
        read_message(client_fd, tag, "received tag");
        print_hex("Client's Encrypted Password", buffer, len);
        decrypt_gcm(buffer, len, tag, key, iv, (unsigned char *)password);
        printf("Client's Decrypted Password: %s\n", password);

        if (authenticate(username, password)) {
            printf("Client authenticated successfully\n");
            len = encrypt_gcm((unsigned char *)"Authentication successful", 26, key, iv, buffer, tag);
            send_message(client_fd, buffer, len);
            send_message(client_fd, tag, 16);

            while (1) {
                const char *menu =
                    "Choose an option:\n"
                    "1) Exit\n"
                    "2) Send a message\n";
                len = encrypt_gcm((unsigned char *)menu, strlen(menu), key, iv, buffer, tag);
                send_message(client_fd, buffer, len);
                send_message(client_fd, tag, 16);

                len = read_message(client_fd, buffer, "received choice");
                read_message(client_fd, tag, "received tag");
                decrypt_gcm(buffer, len, tag, key, iv, dec_buf);

                if (dec_buf[0] == '1') {
                    printf("Client chose exit.\n");
                    break;
                } else if (dec_buf[0] == '2') {
                    const char *prompt = "Enter your message:";
                    len = encrypt_gcm((unsigned char *)prompt, strlen(prompt), key, iv, buffer, tag);
                    send_message(client_fd, buffer, len);
                    send_message(client_fd, tag, 16);

                    len = read_message(client_fd, buffer, "received message");
                    read_message(client_fd, tag, "received tag");
                    decrypt_gcm(buffer, len, tag, key, iv, dec_buf);
                    printf("Client's Decrypted Message: %s\n", dec_buf);

                    const char *ack = "Message received.";
                    len = encrypt_gcm((unsigned char *)ack, strlen(ack), key, iv, buffer, tag);
                    send_message(client_fd, buffer, len);
                    send_message(client_fd, tag, 16);
                    continue;
                } else {
                    const char *bad = "Invalid choice. Please try again.";
                    len = encrypt_gcm((unsigned char *)bad, strlen(bad), key, iv, buffer, tag);
                    send_message(client_fd, buffer, len);
                    send_message(client_fd, tag, 16);
                    printf("Client sent invalid option. Resending menu...\n");
                    continue; 
                }
            }

            break; 
        } else {
            attempts++;
            printf("Client authentication failed - attempt %d\n", attempts);
            if (attempts == maximum_attempts) {
                len = encrypt_gcm((unsigned char *)"Authentication failed. Too many attempts.", 44, key, iv, buffer, tag);
                send_message(client_fd, buffer, len);
                send_message(client_fd, tag, 16);
                printf("Client disconnected after max attempts\n");
                break;
            } else {
                len = encrypt_gcm((unsigned char *)"Authentication failed. Try again.", 36, key, iv, buffer, tag);
                send_message(client_fd, buffer, len);
                send_message(client_fd, tag, 16);
                sleep(1);
            }
        }
    }

    close(client_fd);
    //pthread_mutex_unlock(&log_lock);
    return NULL;
}

int main() {
    int server_fd;
    struct sockaddr_in address;
    socklen_t addrlen = sizeof(address); 

    printf("\n=== Secure Server with Multithreading Started ===\n");

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    bind(server_fd, (struct sockaddr *)&address, sizeof(address));
    listen(server_fd, MAX_CLIENTS);

    printf("Listening on port %d...\n", PORT);

    pthread_mutex_init(&counter_lock, NULL);
    while (1) {
        int *client_fd = malloc(sizeof(int));
        *client_fd = accept(server_fd, (struct sockaddr *)&address, &addrlen);
        if (*client_fd < 0) {
            perror("Accept failed");
            free(client_fd);
            continue;
        }

        pthread_t tid;
        pthread_create(&tid, NULL, handle_client, client_fd);
        pthread_detach(tid);
    }


    pthread_mutex_destroy(&counter_lock);
    //pthread_mutex_lock(&log_lock);
    close(server_fd);
    return 0;
}
