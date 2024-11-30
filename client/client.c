#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define SERVER_ADDR "127.0.0.1"
#define PORT 8080

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX *create_context() {
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        exit(1);
    }
    return ctx;
}

void clear_input_buffer() {
    while (getchar() != '\n' && getchar() != EOF);
}

void handle_SIGPIPE(int err){
    fprintf(stderr, "Received SIGPIPE. Likely the connection was closed.\n");
    return;
}

int main() {
    signal(SIGPIPE, handle_SIGPIPE); // investigate deeper into this one day lol

    int sock;
    struct sockaddr_in server_addr;
    SSL_CTX *ctx;
    SSL *ssl;

    init_openssl();
    ctx = create_context();

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        exit(1);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, SERVER_ADDR, &server_addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Failed while connecting to the server.");
        exit(1);
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) <= 0) {
        perror("SSL_connect failed");
        goto cleanup;
    } else {
        printf("SSL handshake completed\n");
    }

    char write_buffer[256];

    while(1){
        printf("Write: ");
        fflush(stdout);
        scanf("%s", write_buffer);

        ssize_t write_result = SSL_write(ssl, write_buffer, strlen(write_buffer));
        if (write_result <= 0) {
            int err = SSL_get_error(ssl, write_result);
            fprintf(stderr, "SSL write error: %d\n", err);
            break;
        }

        printf("Wrote: %s\n", write_buffer);
        memset(write_buffer, 0, sizeof(write_buffer));
    }
    

    if(SSL_shutdown(ssl) == 0){
        SSL_shutdown(ssl);
    }

    cleanup:
        close(sock);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        cleanup_openssl();
        printf("Client closed\n");
        return 0;
}
