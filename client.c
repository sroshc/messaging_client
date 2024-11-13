#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>

#define SERVER_IP "127.0.0.1"  // Adjust as needed
#define PORT 8181

int main() {
    // Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();

    // Create SSL context
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());

    if (!ctx) {
        printf("Unable to create SSL context\n");
        return -1;
    }

    // Create a socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd < 0) {
        perror("Socket creation failed");
        return -1;
    }

    // Define server address
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    inet_pton(AF_INET, SERVER_IP, &addr.sin_addr);

    // Connect to the server
    if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Connection failed");
        return -1;
    }

    // Create a new SSL connection
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    // Send a request for index.html
    char request[] = "GET /index.html HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
    SSL_write(ssl, request, strlen(request));

    // Receive the server's response
    char buffer[1024] = {0};
    int bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes > 0) {
        printf("Received:\n%s\n", buffer);
    } else {
        printf("No response from server\n");
    }

    // Clean up
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);
    return 0;
}
