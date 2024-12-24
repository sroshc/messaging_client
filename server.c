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

#include "uthash.h"
#include <json-c/json.h>

#include "lib/include/parser.h"
#include "lib/include/userdb.h"
#include "lib/include/termlib.h"
#include "lib/include/hash.h"

#define PORT 8080
#define SOCKETERROR (-1)
#define SERVER_BACKLOG 10
#define MAX_CLIENTS 100

char *S_SERVER_FULL = "{\"response_code\": 501}";
char *S_SERVER_FAILURE = "{\"response_code\": 500}";
char *S_NOT_AUTHORIZED = "{\"response_code\": 401}";
char *S_BAD_REQUEST = "{\"response_code\": 400}";
char *S_SERVER_SUCCESS = "{\"response_code\": 200}";


int server_fd; // Global server file descriptor so signal function can shut it down
pthread_t client_threads[MAX_CLIENTS]; // Holds all handle_connection() threads
int client_fds[MAX_CLIENTS] = { [0 ... MAX_CLIENTS-1] = -1 };  // Holds all currently connected client sockets, this shortcut to set all values to -1 only be used with the GCC compiler
pthread_mutex_t connections_mutex = PTHREAD_MUTEX_INITIALIZER; 


#define SERVER_ONLINE 1
#define SERVER_OFFLINE 0
int SERVER_STATUS = SERVER_ONLINE;

char* DATABASE_NAME = "db";

typedef struct{
    int client_fd;
    SSL_CTX* ctx;
    socklen_t client_socklen;
    struct sockaddr_in client_sockaddr;
    int thread_index;
} t_client_args;

typedef struct{
    int client_fd;
    SSL_CTX* ctx;

} full_client_args;

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
    switch(err) {
        case SSL_ERROR_NONE:
            printf("Client disconnected gracefully\n");
            break;
        case SSL_ERROR_SYSCALL:
            if (errno == EPIPE) {
                printf("Client disconnected with EPIPE (uh oh)\n");
            } else {
                fprintf(stderr, "SSL syscall error: %s\n", strerror(errno));
            }
            break;
        case SSL_ERROR_ZERO_RETURN:
            printf("SSL connection closed by client\n");
            break;
        default:
            fprintf(stderr, "SSL error: %d\n", err);
            ERR_print_errors_fp(stderr);
            break;
    }
    
    return;
}

int j_add_user(sqlite3* db, json_object* jobject, char** username_output){
    int res = BAD_REQUEST;
    json_object* arguments = NULL;
    *username_output = NULL;


    json_object_object_get_ex(jobject, ARGUMENTS, &arguments);

    if(arguments == NULL){
        goto cleanup;
    }
    

    /* Grab username from json */
    char* username = NULL;
    json_object* j_username = NULL;

    json_object_object_get_ex(arguments, USERNAME, &j_username);
    if(j_username == NULL){
        goto cleanup;
    }

    username = (char*) json_object_get_string(j_username);
    if(username == NULL){
        goto cleanup;
    }
    

    /* Grab password from json */
    char* password = NULL;
    json_object* j_password = NULL;

    json_object_object_get_ex(arguments, PASSWORD, &j_password);
    if(j_password == NULL){
        goto cleanup;
    }

    password = (char*) json_object_get_string(j_password);
    if(password == NULL){
        goto cleanup;
    }

    int rc;
    rc = add_user(db, username, password);

    if(rc == DB_SUCCESS){
        res = SUCCESS;
    }

    cleanup:
        if(res == SUCCESS){
            *username_output = malloc(strlen(username) + 1);
            strncpy(*username_output, username, strlen(username)); 
        }
        return res;
}

int j_login_user(sqlite3* db, json_object* jobject, char** username_output){ 
    int res = BAD_REQUEST;
    json_object* arguments = NULL;
    json_object_object_get_ex(jobject, ARGUMENTS, &arguments);

    if(arguments == NULL){
        goto cleanup;
    }


    /* Grab username from arguments */
    json_object* j_username = NULL;
    char* username = NULL;

    json_object_object_get_ex(arguments, USERNAME, &j_username);
    if(j_username == NULL){
        goto cleanup;
    }
    username = (char*) json_object_get_string(j_username);
    if(username == NULL){
        goto cleanup;
    }


    /* Grab paassword from arguments */
    json_object* j_password = NULL; 
    char* password = NULL;

    json_object_object_get_ex(arguments, PASSWORD, &j_password);
    if(j_password == NULL){
        goto cleanup;
    }
    password = (char*) json_object_get_string(j_password);
    if(password == NULL){
        goto cleanup;
    }

    printf("%s trid logging in with: %s\n", username, password);
    res = is_user_valid(db, username, password) == DB_USER_VALID? SUCCESS: NOT_AUTHORIZED;

    cleanup:
        if(res == SUCCESS){
            *username_output = malloc(strlen(username) +1);
            strncpy(*username_output, username, strlen(username)); 
        }
        return res;

}

int j_send_message(sqlite3* db, json_object* jobject, char** username_output){
    int res = BAD_REQUEST;
    
    /* Check if user is logged in properly */
    json_object* j_session_key = NULL;
    const char* session_key = NULL;
    
    json_object_object_get_ex(jobject, SESSION_TOKEN, &j_session_key);

    if(j_session_key == NULL){
        goto cleanup;
    }
    
    session_key = json_object_get_string(j_session_key);
    if(session_key == NULL){
        goto cleanup;
    }


    /* Is the session key valid?*/    
    int sender_id = is_key_valid(session_key);
    if(sender_id == -1){
        res = NOT_AUTHORIZED;
        goto cleanup;
    }



    json_object* arguments = NULL;
    json_object_object_get_ex(jobject, ARGUMENTS, &arguments);

    if(arguments == NULL){
        goto cleanup;
    }


    /*Get the recipient_id*/
    json_object* j_recipient_id = NULL;
    int recipient_id = -1;

    json_object_object_get_ex(arguments, RECIPIENT_ID, &j_recipient_id);

    recipient_id = json_object_get_int(j_recipient_id);

    if(recipient_id <= 0){
        goto cleanup;
    }


    /* Get the content of the message*/
    json_object* j_content = NULL;
    char* content = NULL;

    json_object_object_get_ex(arguments, CONTENT, &j_content);

    if(j_content == NULL){
        goto cleanup;
    }

    content = (char*) json_object_get_string(j_content);
    if(content == NULL){
        goto cleanup;
    }


    int db_res = add_message(db, sender_id, recipient_id, content);
    res = (db_res == DB_SUCCESS ? SUCCESS: SERVER_FAILED); 


    cleanup:
        return res;

}


/* Handling Server Responses */
int res_send_key(SSL* ssl, int user_id){ //Todo: actually add the session key
    json_object *jobj;

    jobj = json_object_new_object();
    json_object_object_add(jobj, "response_code", json_object_new_int64(SUCCESS));

    char *s_key = get_new_session_key(SESSION_KEY_LENGTH);

    printf("%s\n", s_key);

    json_object_object_add(jobj, SESSION_TOKEN, json_object_new_string(s_key));

    const char *final_response = json_object_to_json_string_ext(jobj, JSON_C_TO_STRING_NOSLASHESCAPE); // this flag should be default smh; or have a way to set it as default

    add_session(user_id, s_key);
    SSL_write(ssl, final_response, strlen(final_response));

    free(jobj);
    free(s_key);
    return 1;
}



/* Handling a connection with a client, in a new thread */
void *handle_connection(void *args_input){
    t_client_args* client = NULL;
    client = malloc(sizeof(t_client_args));
    memcpy(client, args_input, sizeof(t_client_args));
    free(args_input);
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
        SSL_write(ssl, S_SERVER_SUCCESS, strlen(S_SERVER_SUCCESS));
    }

    sqlite3* db = NULL; 
    int rc;
    
    rc = sqlite3_open(DATABASE_NAME, &db);

    if(rc != SQLITE_OK){
        SSL_write(ssl, S_SERVER_FAILURE, strlen(S_SERVER_FAILURE));
        goto cleanup;
    }
    
    char receive_buffer[4096];
    json_object * jobject = NULL;
    int bytes_read = 0;
    int command;
    char* username = NULL;

    while(SERVER_STATUS == SERVER_ONLINE && (bytes_read = SSL_read(ssl, receive_buffer, sizeof(receive_buffer) - 1)) > 0){   //TODO: fix
        receive_buffer[bytes_read] = '\0';
        if(bytes_read <= 0){
            int err = SSL_get_error(ssl, bytes_read);
            handle_errors(err);
            break;
        }
        
        command = get_command(receive_buffer, &jobject);
        int res;
                
        switch(command){
            case MAKE_ACCOUNT:
                res = j_add_user(db, jobject, &username);
                if(res == SUCCESS){
                    res_send_key(ssl, get_user_id(db, username));
                    free(username);
                    username = NULL;
                }else{
                    SSL_write(ssl, S_BAD_REQUEST, strlen(S_BAD_REQUEST));
                }
                break;
            case LOGIN:
                res = j_login_user(db, jobject, &username);
                if(res == SUCCESS){
                    res_send_key(ssl, get_user_id(db, username));
                    free(username);
                    username = NULL;
                }else if(res == NOT_AUTHORIZED){
                      SSL_write(ssl, S_NOT_AUTHORIZED, strlen(S_NOT_AUTHORIZED));
                }
                else{
                    SSL_write(ssl, S_BAD_REQUEST, strlen(S_BAD_REQUEST));
                }
                break;
            case SEND_MESSAGE:
                res = j_send_message(db, jobject, &username);
                if(res == SUCCESS){
                    SSL_write(ssl, S_SERVER_SUCCESS, strlen(S_SERVER_SUCCESS));
                }else if(res == NOT_AUTHORIZED){
                    SSL_write(ssl, S_NOT_AUTHORIZED, strlen(S_NOT_AUTHORIZED));
                }else if(res == BAD_REQUEST){
                    SSL_write(ssl, S_BAD_REQUEST, strlen(S_BAD_REQUEST));
                }else{
                    SSL_write(ssl, S_SERVER_FAILURE, strlen(S_SERVER_FAILURE));
                }


            default:
                SSL_write(ssl, S_BAD_REQUEST, strlen(S_BAD_REQUEST));
        }
        
        printf("Read from client %s: %s\n", client_ip, receive_buffer);
        printf("Current USERS table:\n");
        print_all(db, "USERS");
        printf("Current session keys:\n");
        print_all_keys();
        if(jobject) json_object_put(jobject);
        jobject = NULL;
    }


    cleanup:
        if(db) sqlite3_close(db);
        if(jobject) json_object_put(jobject);
        jobject = NULL;
        if(username) free(username);
        username = NULL;

        pthread_mutex_lock(&connections_mutex);
        client_fds[client->thread_index] = -1;
        pthread_mutex_unlock(&connections_mutex);

        if (ssl) {
            int shutdown_result = SSL_shutdown(ssl);
            if (shutdown_result == 0) {
                SSL_shutdown(ssl);
            }
            
            int err_code = SSL_get_error(ssl, bytes_read);
            if (err_code != SSL_ERROR_NONE) {
                handle_errors(err_code);
            }
            
            SSL_free(ssl);
        }

        close(client->client_fd);
        
        printf("Closed connection with %s\n", client_ip);

        if(client) free(client); 
        client = NULL;
                
        return NULL;
}


//TODO: make this multithreaded if you feel like it
void handle_client_limit(int client_fd, SSL_CTX* ctx){
    SSL *ssl = NULL;
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_fd);

    if (SSL_accept(ssl) <= 0) {
        unsigned long err_code = ERR_get_error();
        fprintf(stderr, "SSL handshake failed: %s (server full)\n", ERR_error_string(err_code, NULL));
        if(ssl)SSL_shutdown(ssl);
        return;
    } else{
        printf("SSL handshake completed (server full)\n");
    }

    SSL_write(ssl, S_SERVER_FULL, strlen(S_SERVER_FULL));

    if (ssl) {
        int shutdown_result = SSL_shutdown(ssl);
        if (shutdown_result == 0) {
            SSL_shutdown(ssl);
        }
        SSL_free(ssl);
    }    
    close(client_fd);

    return;
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

    pthread_mutex_lock(&connections_mutex);
    SERVER_STATUS = SERVER_OFFLINE;
    pthread_mutex_unlock(&connections_mutex);
    
    return;
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

    int optval = 1;
    if(setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0){
        perror("Setting socket options for SO_REUSEADDR failed. Continuing.");
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

        pthread_mutex_lock(&connections_mutex);
        thread_index = -1;
        for(int i = 0; i < MAX_CLIENTS; i++){
            if(client_fds[i] == -1){
                thread_index = i;
                client_fds[i] = client_fd;
                break;
            }
        }
        pthread_mutex_unlock(&connections_mutex);

        if(thread_index == -1){
            handle_client_limit(client_fd, ctx);
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

        pthread_mutex_lock(&connections_mutex);
        client_threads[thread_index] = t;
        pthread_mutex_unlock(&connections_mutex);

        pthread_create(&t, NULL, handle_connection, args);
        pthread_detach(t);
    }

    SSL_CTX_free(ctx);
    cleanup_openssl();
    return 0;
}

