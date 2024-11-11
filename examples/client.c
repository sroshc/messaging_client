#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define SERVER_PORT 4433
#define SERVER_ADDR "127.0.0.1"
#define CERT_FILE "server.crt"  // The server's self-signed certificate
#define BUF_SIZE 1024

void init_openssl() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
}

SSL_CTX* create_ssl_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_client_method();  // Choose TLS (or SSL)
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_ssl_context(SSL_CTX *ctx) {
    // Load the server's self-signed certificate into the context
    if (SSL_CTX_load_verify_locations(ctx, CERT_FILE, NULL) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Set the verification mode to verify the server's certificate against the loaded certificate
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
}

void connect_to_server(SSL_CTX *ctx, const char *server_addr, int server_port) {
    int sock;
    struct sockaddr_in server;
    SSL *ssl;
    char buffer[BUF_SIZE];

    // Create a TCP socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    server.sin_family = AF_INET;
    server.sin_port = htons(server_port);
    server.sin_addr.s_addr = inet_addr(server_addr);

    // Connect to the server
    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) != 0) {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }

    // Create an SSL structure
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);  // Associate the SSL object with the socket

    // Perform SSL/TLS handshake with the server
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Verify the server's certificate (using the self-signed certificate)
    if (SSL_get_verify_result(ssl) != X509_V_OK) {
        fprintf(stderr, "Certificate verification failed\n");
        exit(EXIT_FAILURE);
    }

    printf("Successfully connected to the server via SSL/TLS\n");

    // Send a message to the server
    const char *msg = "Hello from client!";
    SSL_write(ssl, msg, strlen(msg));

    // Read the server's response
    int bytes_read = SSL_read(ssl, buffer, sizeof(buffer));
    if (bytes_read > 0) {
        buffer[bytes_read] = 0;  // Null-terminate the string
        printf("Received from server: %s\n", buffer);
    }

    // Clean up SSL connection and socket
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
}

int main() {
    SSL_CTX *ctx;

    // Initialize OpenSSL library
    init_openssl();

    // Create an SSL context
    ctx = create_ssl_context();

    // Configure the SSL context to trust the self-signed certificate
    configure_ssl_context(ctx);

    // Connect to the SSL server
    connect_to_server(ctx, SERVER_ADDR, SERVER_PORT);

    // Clean up SSL context
    SSL_CTX_free(ctx);
    return 0;
}
