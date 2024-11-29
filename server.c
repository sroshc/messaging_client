#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <pthread.h>
#include <sqlite3.h>
#include "uthash.h"
#include <stdbool.h>
#include <signal.h>

#include "lib/include/parser.h"
#include "lib/include/userdb.h"
#include "lib/include/termlib.h"
#include "lib/include/hash.h"

#define PORT 8080
#define SOCKETERROR (-1)
#define SERVER_BACKLOG 10

const char* DATABASE_NAME = "db";

typedef struct{
    int client_fd;
    SSL_CTX* ctx;
    socklen_t client_socklen;
    struct sockaddr_in client_sockaddr;
} t_client_args;

void init_db(){
    create_database(DATABASE_NAME);
}

sqlite3* get_db_connection(){
    sqlite3* db;
    int rc;

    rc = sqlite3_open(DATABASE_NAME, &db);

    if(rc != SQLITE_OK){
        return NULL;
    }

    return db;
}


void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX *create_context() {
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Creating SSL context failed.");
        exit(1);
    }
    return ctx;
}

void configure_context(SSL_CTX *ctx) {
    SSL_CTX_set_ecdh_auto(ctx, 1);
    if (SSL_CTX_use_certificate_file(ctx, "lib/keys/server.crt", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, "lib/keys/server.key", SSL_FILETYPE_PEM) <= 0) {
        perror("Configuring SSL context failed.");
        exit(1);
    }
}

int check(int event, const char* msg){
    if(event == SOCKETERROR){
        perror(msg);
        exit(1);
    }

    return event;
}

void handle_errors(int err){
    if (err == SSL_ERROR_ZERO_RETURN) {
        printf("Client disconnected gracefully\n");
    } else if (err == SSL_ERROR_SYSCALL) {
        if (errno == EPIPE) {
            printf("Client disconnected with errors\n");
        } else {
            fprintf(stderr, "SSL error: %s\n", strerror(errno));
        }
    } else {
        fprintf(stderr, "SSL error: %d\n", err);
    }

    if(err == 1){
        printf("(likely not an error)\n");
    }
}

void *handle_connection(void *args_input){
    t_client_args* client = (t_client_args *) args_input;
    SSL *ssl = SSL_new(client->ctx);
    SSL_set_fd(ssl, client->client_fd);
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client->client_sockaddr.sin_addr, client_ip, INET_ADDRSTRLEN);

    if (SSL_accept(ssl) <= 0) {
        unsigned long err_code = ERR_get_error();
        fprintf(stderr, "SSL handshake failed with %s: %s\n", client_ip, ERR_error_string(err_code, NULL));
        goto cleanup;
    } else {
        printf("SSL handshake completed with %s\n", client_ip);
    }
    
    char receive_buffer[4096];
    int bytes_read;
    int command;

    while((bytes_read = SSL_read(ssl, receive_buffer, sizeof(receive_buffer) - 1)) > 0){   
        receive_buffer[bytes_read] = '\0';
        printf("Read from client %s: %s\n", client_ip, receive_buffer);
    }


    cleanup:
        close(client->client_fd);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        free(client);

        int err_code = SSL_get_error(ssl, bytes_read);
        handle_errors(err_code);

        printf("Closed connection with %s\n", client_ip);
        return NULL;
}

void handle_SIGPIPE(int err){
    return;
}

int main() {
    signal(SIGPIPE, handle_SIGPIPE); // investigate deeper into this one day lol
    int server_fd, client_fd;
    struct sockaddr_in addr;
    SSL_CTX *ctx;

    init_db();
    init_openssl();
    ctx = create_context();
    configure_context(ctx);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("Socket creation failed");
        exit(1);
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    check(bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)), "Bind failed.");
    check(listen(server_fd, 1), "Listen failed.");

    printf("Listening on port %d...\n", PORT);


    struct sockaddr_in client_addr;
    socklen_t socklen = sizeof(client_addr);

    while(1){
        check(client_fd = accept(server_fd, (struct sockaddr *) &client_addr, &socklen), "Accept failed.");
        
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);

        printf("Connection from %s\n", client_ip);
        
        pthread_t  t;
        
        t_client_args* args = malloc(sizeof(t_client_args));

        if(args == NULL){
            perror("Failed allocating memory for arguments.");
            close(client_fd);
            continue;
        }        
        
        args->client_fd = client_fd;
        args->ctx = ctx;
        args->client_socklen = socklen;
        args->client_sockaddr = client_addr;

        pthread_create(&t, NULL, handle_connection, args);
        pthread_detach(t);

    }

    SSL_CTX_free(ctx);
    close(server_fd);
    cleanup_openssl();
    return 0;
}

