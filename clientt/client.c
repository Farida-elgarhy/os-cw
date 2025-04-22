#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define PORT 8080
#define BUFFER_SIZE 1024

void remove_newline(char *str) {
    for (int i = 0; str[i]; i++) {
        if (str[i] == '\n') {
            str[i] = '\0';
            break;
        }
    }
}

void send_message(int sock, unsigned char *data, int len, const char *error_msg) {
    uint32_t net_len = htonl(len);
    if (send(sock, &net_len, sizeof(net_len), 0) < 0 ||
        send(sock, data, len, 0) < 0) {
        perror(error_msg);
        close(sock);
        exit(EXIT_FAILURE);
    }
}

int read_message(int sock, unsigned char *buf, const char *err_msg) {
    uint32_t net_len;
    if (recv(sock, &net_len, sizeof(net_len), MSG_WAITALL) <= 0) {
        perror("Length read failed");
        close(sock);
        exit(EXIT_FAILURE);
    }
    int len = ntohl(net_len);
    if (recv(sock, buf, len, MSG_WAITALL) <= 0) {
        perror(err_msg);
        close(sock);
        exit(EXIT_FAILURE);
    }
    return len;
}

void strToHex(const char *label, unsigned char *data, int len) {
    printf("%s: ", label);
    for (int i = 0; i < len; i++) printf("%02X", data[i]);
    printf("\n");
}

int encrypt_gcm(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv,
                unsigned char *enc_buf, unsigned char *tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, enc_len;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);

    EVP_EncryptUpdate(ctx, enc_buf, &len, plaintext, plaintext_len);
    enc_len = len;

    EVP_EncryptFinal_ex(ctx, enc_buf + len, &len);
    enc_len += len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
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

int main() {
    int sock;
    struct sockaddr_in server_address;
    char username[50], password[50];
    unsigned char key[32], iv[12];
    unsigned char buffer[BUFFER_SIZE], enc_buf[BUFFER_SIZE], dec_buf[BUFFER_SIZE];
    unsigned char tag[16];
    int enc_len;
    char choice[8];

    const char *success_msg = "Authentication successful";
    const char *fail_msg = "Authentication failed. Too many attempts.";

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(PORT);
    server_address.sin_addr.s_addr = INADDR_ANY;

    if (connect(sock, (struct sockaddr*)&server_address, sizeof(server_address)) < 0) {
        perror("Connection failed");
        close(sock);
        exit(EXIT_FAILURE);
    }

    printf("\n=== Secure Client Started ===\n\n");

    if (read(sock, key, 32) != 32 || read(sock, iv, 12) != 12) {
        perror("Failed to receive key/IV");
        close(sock);
        exit(EXIT_FAILURE);
    }
    printf("Received encryption key and IV from server\n");

    while (1) {
        enc_len = read_message(sock, buffer, "received username");
        read_message(sock, tag, "received tag username");
        decrypt_gcm(buffer, enc_len, tag, key, iv, dec_buf);
        printf("\n %s", dec_buf);

        fgets(username, sizeof(username), stdin);
        remove_newline(username);
        enc_len = encrypt_gcm((unsigned char *)username, strlen(username), key, iv, enc_buf, tag);
        send_message(sock, enc_buf, enc_len, "send username");
        send_message(sock, tag, 16, "send tag username");

        enc_len = read_message(sock, buffer, "recv prompt password");
        read_message(sock, tag, "recv tag password");
        decrypt_gcm(buffer, enc_len, tag, key, iv, dec_buf);
        printf(" %s", dec_buf);

        fgets(password, sizeof(password), stdin);
        remove_newline(password);
        enc_len = encrypt_gcm((unsigned char *)password, strlen(password), key, iv, enc_buf, tag);
        send_message(sock, enc_buf, enc_len, "send password");
        send_message(sock, tag, 16, "send tag password");

        enc_len = read_message(sock, buffer, "recv auth result");
        read_message(sock, tag, "recv tag auth");
        decrypt_gcm(buffer, enc_len, tag, key, iv, dec_buf);
        printf("\n Server: %s\n", dec_buf);

        if (strncmp((char *)dec_buf, success_msg, strlen(success_msg)) == 0) {
            break;
        }

        if (strncmp((char *)dec_buf, fail_msg, strlen(fail_msg)) == 0) {
            close(sock);
            return 0;
        }
    }

    while (1) {                           
        /* ---- receive & print menu ---- */
        enc_len = read_message(sock, buffer, "menu text");
        read_message(sock, tag, "menu tag");
        decrypt_gcm(buffer, enc_len, tag, key, iv, dec_buf);
        printf("\n%s", dec_buf);
    
        /* ---- get user choice, send ---- */
        fgets(choice, sizeof(choice), stdin);
        remove_newline(choice);
        enc_len = encrypt_gcm((unsigned char *)choice, strlen(choice),
                              key, iv, enc_buf, tag);
        send_message(sock, enc_buf, enc_len, "send choice");
        send_message(sock, tag, 16, "tag choice");
    
        if (choice[0] == '1') {                 
            printf("Exiting as requested.\n");
            break;                             
        } else if (choice[0] == '2') {         
            /* receive prompt */
            enc_len = read_message(sock, buffer, "message prompt");
            read_message(sock, tag, "prompt tag");
            decrypt_gcm(buffer, enc_len, tag, key, iv, dec_buf);
            printf("%s ", dec_buf);

            /* get user input and send */
            fgets((char *)buffer, BUFFER_SIZE, stdin);
            remove_newline((char *)buffer);
            enc_len = encrypt_gcm(buffer, strlen((char *)buffer), key, iv, enc_buf, tag);
            send_message(sock, enc_buf, enc_len, "send msg");
            send_message(sock, tag, 16, "msg tag");

            /* read acknowledgment from server */
            enc_len = read_message(sock, buffer, "server ack");
            read_message(sock, tag, "ack tag");
            decrypt_gcm(buffer, enc_len, tag, key, iv, dec_buf);
            printf("Server: %s\n", dec_buf);

            continue;
        } else if (choice[0] == '3') {
            // NEW: Receive role-based Files menu from server
            enc_len = read_message(sock, buffer, "file menu recv");
            read_message(sock, tag, "file menu tag");
            decrypt_gcm(buffer, enc_len, tag, key, iv, dec_buf);
            printf("\n%s", dec_buf);
            continue;
        } else {                             
            enc_len = read_message(sock, buffer, "invalid resp");
            read_message(sock, tag, "invalid tag");
            decrypt_gcm(buffer, enc_len, tag, key, iv, dec_buf);
            printf("Server: %s\n", dec_buf);
            continue;
        }
    }

    close(sock);
    return 0;
}
