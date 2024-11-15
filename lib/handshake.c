#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdio.h>

#define ENCRYPTED_LENGTH 256

typedef struct Sym_key{
    unsigned char key[32];
    unsigned char iv[16];
}Sym_key;
/*
typedef struct RSA_key{
    unsigned char
}
*/
Sym_key* init_sym_key(){
    Sym_key *k = malloc(sizeof(Sym_key));
    RAND_bytes(k->key, 32);
    RAND_bytes(k->iv, 16);

    return k;
} 

void free_sym_key(Sym_key* key){
    free(key);
    return;
}

void handleErrors(){
    ERR_print_errors_fp(stderr);
    abort();
}

static int _sym_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

static int _sym_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

unsigned char* sym_encrypt(Sym_key *k, char* plaintext, int* ciphertext_len){
    int plaintext_len = strlen(plaintext);

    unsigned char *ciphertext = malloc(plaintext_len + EVP_MAX_BLOCK_LENGTH);

    *ciphertext_len = _sym_encrypt((unsigned char *)plaintext, strlen(plaintext), k->key, k->iv, ciphertext);
    
    ciphertext = realloc(ciphertext, *ciphertext_len);


    return ciphertext;
}

char *sym_decrypt(Sym_key *k, unsigned char* ciphertext, int ciphertext_len){
    int decryptedtext_len;

    char *decryptedtext = malloc(ciphertext_len + 1);

    decryptedtext_len = _sym_decrypt(ciphertext, ciphertext_len, k->key, k->iv, (unsigned char *)decryptedtext);
   
    decryptedtext[decryptedtext_len] = '\0';

    return decryptedtext;
}

typedef struct RSA_key{
    EVP_PKEY* privatekey;
    EVP_PKEY* publickey;
    EVP_PKEY_CTX* ctx;
}RSA_key;

RSA_key* init_rsa_key(char* private_file, char* public_file){
    RSA_key* key = malloc(sizeof(RSA_key));
    FILE *pFile;


    pFile = fopen(private_file, "r");
    if (!pFile) {
        perror("Error opening private key file");
        free(key);
        return NULL;
    }
    key->privatekey = PEM_read_PrivateKey(pFile, NULL, NULL, NULL);
    fclose(pFile);
    if (!key->privatekey) {
        handleErrors();
    }
    
    // Load the public key
    pFile = fopen(public_file, "r");
    if (!pFile) {
        perror("Error opening public key file");
        free(key->privatekey);
        free(key);
        return NULL;
    }

    key->publickey = PEM_read_PUBKEY(pFile, NULL, NULL, NULL);
    if (!key->privatekey) {
        handleErrors();
    }

    fclose(pFile);


    key->ctx = EVP_PKEY_CTX_new(key->publickey, NULL);
    if (!key->ctx) {
        handleErrors();
    }
    
    if (EVP_PKEY_encrypt_init(key->ctx) <= 0) {
        handleErrors();
    }

    return key;
}

void change_ctx(RSA_key* key, EVP_PKEY* pkey){
    EVP_PKEY_CTX_free(key->ctx);
    key->ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!key->ctx) {
        handleErrors();
    }
    
    return;
}

void free_rsa_key(RSA_key* key){
    EVP_PKEY_free(key->privatekey);
    EVP_PKEY_free(key->publickey);
    EVP_PKEY_CTX_free(key->ctx);
    free(key);

    return;
}

void test_sym_encrypt(){
    Sym_key* key = init_sym_key();
    int ciphertext_len;

    unsigned char* ciphertext = sym_encrypt(key, "The quick brown fox jumps over the lazy dog.", &ciphertext_len);
    char* decryptedtext = sym_decrypt(key, ciphertext, ciphertext_len);
    printf("%s\n", decryptedtext);
}


int main(void) {
    RSA_key* key = init_rsa_key("private_key.pem", "public_key.pem");
    
    unsigned char *encrypted = NULL, *decrypted = NULL;
    unsigned char data[] = "Hello, this is a test message!";
    size_t encrypted_length, decrypted_length;
    
    
    if (EVP_PKEY_encrypt(key->ctx, NULL, &encrypted_length, data, strlen((char *)data)) <= 0) {
        handleErrors();
    }
    
    encrypted = malloc(encrypted_length);

    if (!encrypted) {
        perror("Memory allocation failed");
        return 1;
    }
    
    // Perform the actual encryption
    if (EVP_PKEY_encrypt(key->ctx, encrypted, &encrypted_length, data, strlen((char *)data)) <= 0) {
        handleErrors();
    }
    
    printf("Encrypted data length: %zu\n", encrypted_length);
    
    
    change_ctx(key, key->privatekey);
    

    if (EVP_PKEY_decrypt_init(key->ctx) <= 0) {
        handleErrors();
    }
    
    // Determine the buffer size required for decrypted data
    if (EVP_PKEY_decrypt(key->ctx, NULL, &decrypted_length, encrypted, ENCRYPTED_LENGTH) <= 0) {
        handleErrors();
    }
    
    decrypted = malloc(decrypted_length+1);
    if (!decrypted) {
        perror("Memory allocation failed");
        return 1;
    }
    
    // Perform the actual decryption
    if (EVP_PKEY_decrypt(key->ctx, decrypted, &decrypted_length, encrypted, encrypted_length) <= 0) {
        handleErrors();
    }
    decrypted[decrypted_length] = '\0';
    
    printf("Decrypted message: %s\n", decrypted);
    
    // Clean up
    free_rsa_key(key);
    free(encrypted);
    free(decrypted);
    
    return 0;
}




    // /*
    //  * Set up the key and iv. Do I need to say to not hard code these in a
    //  * real application? :-)
    //  */

    // /* A 256 bit key */
    // unsigned char key[256];

    // /* A 128 bit IV */
    // unsigned char iv[128];

    // RAND_bytes(key, 256);
    // RAND_bytes(iv, 128);

    // /* Message to be encrypted */
    // char *plaintext =
    //         "The quick brown fox jumps over the lazy dog";
    // /*
    //  * Buffer for ciphertext. Ensure the buffer is long enough for the
    //  * ciphertext which may be longer than the plaintext, depending on the
    //  * algorithm and mode.
    //  */
    // unsigned char ciphertext[128];

    // /* Buffer for the decrypted text */
    // unsigned char decryptedtext[128];

    // int decryptedtext_len, ciphertext_len;

    // /* Encrypt the plaintext */
    // ciphertext_len = _sym_encrypt ((unsigned char*)plaintext, strlen (plaintext), key, iv,
    //                           ciphertext);

    // /* Do something useful with the ciphertext here */

    // /* Decrypt the ciphertext */
    // decryptedtext_len = _sym_decrypt(ciphertext, ciphertext_len, key, iv,
    //                             decryptedtext);

    // /* Add a NULL terminator. We are expecting printable text */
    // decryptedtext[decryptedtext_len] = '\0';

    // /* Show the decrypted text */
    // printf("Decrypted text is:\n");
    // printf("%s\n", decryptedtext);
    // printf("Actual text: %s\n", plaintext);

    // return 0;