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
#define MAX_CLIENTS 100

int server_fd; // Global server file descriptor so signal function can shut it down
pthread_t client_threads[MAX_CLIENTS]; // Holds all handle_connection() threads
int client_fds[MAX_CLIENTS] = {-1};   // Holds all currently connected client sockets
pthread_mutex_t connections_mutex = PTHREAD_MUTEX_INITIALIZER; 


#define SERVER_ONLINE 1
#define SERVER_OFFLINE 0
int SERVER_STATUS = SERVER_ONLINE;

const char* DATABASE_NAME = "db";



typedef struct{
    int client_fd;
    SSL_CTX* ctx;
    socklen_t client_socklen;
    struct sockaddr_in client_sockaddr;
    int thread_index;
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

// Should only be used with functions with possible critical errors 
int check(int event, const char* msg){  
    if(event == SOCKETERROR){
        perror(msg);
        exit(1);
    }

    return event;
}

void handle_errors(int err){
    if (err == SSL_ERROR_NONE) {
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
    ERR_print_errors_fp(stderr);
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
    int bytes_read = 0;
    int command;

    while(SERVER_STATUS == SERVER_ONLINE && (bytes_read = SSL_read(ssl, receive_buffer, sizeof(receive_buffer) - 1)) > 0){   
        receive_buffer[bytes_read] = '\0';
        if(bytes_read <= 0){
            int err = SSL_get_error(ssl, bytes_read);
            handle_errors(err);
            break;
        }
        printf("Read from client %s: %s\n", client_ip, receive_buffer);
    }


    cleanup:
        pthread_mutex_lock(&connections_mutex);
        client_fds[client->thread_index] = -1;
        if(SSL_shutdown(ssl) == 0){
            SSL_shutdown(ssl);
        }     
        close(client->client_fd);
        SSL_free(ssl);
        free(client);

        int err_code = SSL_get_error(ssl, bytes_read);
        handle_errors(err_code);
        pthread_mutex_unlock(&connections_mutex);

        printf("Closed connection with %s\n", client_ip);
        return NULL;
}


// TODO: Inform client that server is full there are the max amount of connection threads
void handle_client_limit(int client_fd, SSL_CTX* ctx){
    write(client_fd, "Full!", 6);

    // SSL *ssl = SSL_new(client->ctx);
    // SSL_set_fd(ssl, client_fd);

    // if (SSL_accept(ssl) <= 0) {
    //     unsigned long err_code = ERR_get_error();
    //     fprintf(stderr, "SSL handshake failed with %s: %s\n", client_ip, ERR_error_string(err_code, NULL));
    //     goto cleanup;
    // } else{
    //     printf("SSL handshake completed with %s\n", client_ip);
    // }

}

void handle_SIGPIPE(int err){
    fprintf(stderr, "Received SIGPIPE. The connection was likely closed.\n");    
    return;
}


void quit_handler(int err){
    printf("Shutting down server...\n");

    pthread_mutex_lock(&connections_mutex);
    for(int i = 0; i < MAX_CLIENTS; i++){
        if(client_fds[i] != -1){
            close(client_fds[i]);
        }
    }
    pthread_mutex_unlock(&connections_mutex);

    printf("Closed all client connections.\n");

    close(server_fd);

    printf("Stopped listening for new connections.\n");

    SERVER_STATUS = SERVER_OFFLINE;
    
}



int main() {
    signal(SIGPIPE, handle_SIGPIPE); // investigate deeper into this one day lol
    signal(SIGINT, quit_handler);

    int client_fd;
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

    check(bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)), "Bind failed");
    check(listen(server_fd, SERVER_BACKLOG), "Listen failed");

    printf("Listening on port %d...\n", PORT);


    struct sockaddr_in client_addr;
    socklen_t socklen = sizeof(client_addr);
    int thread_index;

    while(SERVER_STATUS == SERVER_ONLINE){
        int accept_result = client_fd = accept(server_fd, (struct sockaddr *) &client_addr, &socklen);
        
        if(accept_result == SOCKETERROR){
            printf("Breaking out of listening loop\n");
            break;
        }


        thread_index = -1;
        for(int i = 0; i < MAX_CLIENTS; i++){
            if(client_fds[i] == -1){
                thread_index = i;
                pthread_mutex_lock(&connections_mutex);
                client_fds[i] = client_fd;
                pthread_mutex_unlock(&connections_mutex);
                break;
            }
        }
        

        if(thread_index == -1){ //TODO: Actually write data to client telling it that server is full
            close(client_fd);
            continue;
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);

        printf("Connection from %s\n", client_ip);
        
        pthread_t t;
        
        t_client_args* args = malloc(sizeof(t_client_args));

        if(args == NULL){
            perror("Failed allocating memory for arguments.");
            client_fds[thread_index] = -1; 
            close(client_fd);
            continue;
        }
        
        args->client_fd = client_fd;
        args->ctx = ctx;
        args->client_socklen = socklen;
        args->client_sockaddr = client_addr;
        args->thread_index = thread_index;


        pthread_create(&t, NULL, handle_connection, args);

        pthread_mutex_lock(&connections_mutex);
        client_threads[thread_index] = t;
        pthread_mutex_unlock(&connections_mutex);

        pthread_detach(t);
    }

    SSL_CTX_free(ctx);
    cleanup_openssl();
    return 0;
}

