#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <string.h>

#define crt "server.crt"
#define KEY "server.key"
#define PORT 8181

#define NOT_AUTHORIZED "NOT_AUTHORIZED"
#define AUTHORIZED "AUTHORIZED"
#define FAILED "FAILED"
#define SUCCESS "SUCCESS"

int main(){
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;



    bind(sockfd, (struct sockaddr*)&addr, sizeof(addr));
    listen(sockfd, 10);

    struct sockaddr_in client_address;
    int client_addrlen = sizeof(client_address);

    int clientfd = accept(sockfd, (struct sockaddr *)&client_address, &client_addrlen);

    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, clientfd);
    SSL_CTX_use_certificate_file(ctx, KEY, SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, KEY, SSL_FILETYPE_PEM);
    SSL_accept(ssl);
    char buffer[1024] = {0};
    SSL_read(ssl, buffer, 1023);
    // GET /file     
    
    char* file_request = buffer + 5;
    char response[1024] = {0};
    char* metadata = "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n";

    memcpy(response, metadata, strlen(metadata));

    if (strncmp(file_request, "index.html ", 11) == 0){
        FILE *f = fopen("index.html", "r");
        fread(response + strlen(metadata), 1024 - strlen(metadata)-1, 1, f);

        fclose(f);
        
    }else{
        char *error = "No page found";
        memcpy(response + strlen(metadata), error, strlen(error));
    }

    SSL_write(ssl, response, 1024);

    SSL_shutdown(ssl);


}