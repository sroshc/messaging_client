#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <pthread.h>
#include <sqlite3.h>
#include <stdbool.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/epoll.h>

#include "uthash.h"
#include <json-c/json.h>

#include "lib/include/parser.h"
#include "lib/include/userdb.h"
#include "lib/include/termlib.h"
#include "lib/include/hash.h"

#define PORT 8080
#define SOCKETERROR (-1)
#define SERVER_BACKLOG 100
#define MAX_CLIENTS 100
#define EPOLL_MAX_EVENTS

char *S_SERVER_FULL = "{\"response_code\": 501}";
char *S_SERVER_FAILURE = "{\"response_code\": 500}";
char *S_NOT_AUTHORIZED = "{\"response_code\": 401}";
char *S_BAD_REQUEST = "{\"response_code\": 400}";
char *S_SERVER_SUCCESS = "{\"response_code\": 200}";


int server_fd; // Global server file descriptor so signal function can shut it down

#define SERVER_ONLINE 1
#define SERVER_OFFLINE 0

int SERVER_STATUS = SERVER_ONLINE;

const char* DATABASE_NAME = "db";




void init_db(){
    create_database((char*)DATABASE_NAME);
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

void set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    return;
}

// Should only be used with functions with possible critical errors 
int check(int event, int err_num,const char* msg){  
    if(event == err_num){
        perror(msg);
        perror("Critical error, exiting!");
        exit(1);
    }

    return event;
}

void quit_handler(int err){ //Update this to eventually close all parts of the server
    printf("Shutting down!");
    
    return;
}


int main(){
    int res;
    signal(SIGINT, quit_handler);

    //Initilizations
    init_openssl();
    init_db();
    SSL_CTX *ctx = create_context();
    configure_context(ctx);


    //Create, configure, and bind server socket
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    
    if(setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &res, sizeof(res)) < 0){
        perror("Setting socket options for SO_REUSEADDR failed. Continuing.");
    }

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port = htons(PORT),
    };

    check(bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)), SOCKETERROR, "Bind failed.\n");
    check(listen(server_fd, SERVER_BACKLOG), SOCKETERROR, "Listen failed.\n");
    set_nonblocking(server_fd);

    printf("Listening on port %d...\n", PORT);


    //Create the static epoll instance 
    struct epoll_event ev, events[EPOLL_MAX_EVENTS];
    int nfds, epollfd;

    epollfd = check(epoll_create1(0), -1, "Creating epoll instance with epoll_create1(0) failed.\n"); //epoll_create() is depracted since the max clients dont matter to it anymore or sum idk ask richard
    ev.events = EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLRDHUP; //Notified when new data is available, when a socket disconnects, or when an error occurs on a socket
    ev.data.fd = server_fd;
    check(epoll_ctl(epollfd, EPOLL_CTL_ADD, server_fd, &ev), -1, "Control epoll_ctl() failed.");

    int client_fd;
    struct sockaddr 
    // Main Server Loop
    while(SERVER_STATUS == SERVER_ONLINE){
        nfds = epoll_wait(epoll_fd, events, EPOLL_MAX_EVENTS, -1); // Can set a timeout later on
        check(nfds, -1, "Blocking epoll_wait() failed.");
        
        for(i = 0; i < nfds; i++){
            if(events[i].data.fd == server_fd){
                
            }
        
        }

    }
    
}