#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define SERVER_ADDR "127.0.0.1"
#define PORT 8080

bool is_server_online = true;

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

typedef struct{
    SSL* ssl;
} server_ssl_args;

void* handle_server_responses(void* ssl){
    server_ssl_args *server_args = (server_ssl_args *) ssl; 
    char receive_buffer[4096];

    while(1){
        int res = SSL_read(server_args->ssl, receive_buffer, sizeof(receive_buffer) -1);
        if(res <= 0){
            return NULL;
        }
        receive_buffer[res - 1] = '\0';

        printf("Server sent: %s\n", receive_buffer);
    }
}

void quit_handler(int err){
    is_server_online = false;
}

int main() {
    signal(SIGPIPE, handle_SIGPIPE); // investigate deeper into this one day lol
    signal(SIGINT, quit_handler);


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

    pthread_t read_thread;

    server_ssl_args *server_ssl;

    server_ssl = malloc(sizeof(server_ssl_args));
    server_ssl->ssl = ssl;

    pthread_create(&read_thread, NULL, handle_server_responses, server_ssl);
    pthread_detach(read_thread);

    FILE* file;
    char write_buffer[4096];
    char filename[256];

    while(is_server_online) {
        printf("File to write: ");
        fflush(stdout);
        scanf("%s", filename);  

        file = fopen(filename, "rb");  
        if (file == NULL) {
            printf("File \"%s\" does not exist.\n", filename);
            continue;
        }

        size_t read_size;
        while ((read_size = fread(write_buffer, 1, sizeof(write_buffer), file)) > 0) {
            ssize_t write_result = SSL_write(ssl, write_buffer, read_size);
            if (write_result <= 0) {
                int err = SSL_get_error(ssl, write_result);
                fprintf(stderr, "SSL write error: %d\n", err);
                fclose(file);
                goto cleanup;
            }
            printf("Wrote: %.*s\n", (int)read_size, write_buffer);
        }

        fclose(file);
    }



    cleanup:
        if(SSL_shutdown(ssl) == 0){
            SSL_shutdown(ssl);
        }
        close(sock);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        cleanup_openssl();
        printf("Client closed\n");
        return 0;
}
