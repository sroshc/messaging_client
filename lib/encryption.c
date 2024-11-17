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

int change_ctx_encrypt(RSA_key* key){
    if(key->ctx) EVP_PKEY_CTX_free(key->ctx);

    key->ctx = EVP_PKEY_CTX_new(key->publickey, NULL);
    if(EVP_PKEY_encrypt_init(key->ctx) <= 0){
        return -1;
    }
    if (!key->ctx) {
        return -1;
    }

    return 0;
}

int change_ctx_decrypt(RSA_key* key){
    if(key->ctx) EVP_PKEY_CTX_free(key->ctx);

    key->ctx = EVP_PKEY_CTX_new(key->privatekey, NULL);
    if(EVP_PKEY_decrypt_init(key->ctx) <= 0){
        return -1;
    }
    if (!key->ctx) {
        return -1;
    }
    
    return 0;
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

typedef struct plaintext_cipher_pair{
    unsigned char* ptext;
    unsigned char* ctext;

}Ptext_ctext_pair;

Ptext_ctext_pair* init_rsa_pair(){
    Ptext_ctext_pair* res = malloc(sizeof(Ptext_ctext_pair));
    
    res->ptext = NULL;
    res->ctext = NULL;

    return res;
}

void free_rsa_pair(Ptext_ctext_pair* pair){
    if(pair->ptext) free(pair->ptext);
    if(pair->ctext) free(pair->ctext);
    free(pair);

    return;
}

int rsa_encrypt_pair(RSA_key* key, Ptext_ctext_pair* pair) {
    if (change_ctx_encrypt(key) != 0) {
        return -1;
    }

    if (!pair->ptext) {
        return -1;
    }
    if (pair->ctext) {
        free(pair->ctext);
    }

    size_t encrypted_length;
    pair->ctext = malloc(EVP_PKEY_get_size(key->publickey));

    if (EVP_PKEY_encrypt(key->ctx, pair->ctext, &encrypted_length, pair->ptext, strlen((char *)pair->ptext)) <= 0) {
        return -1;
    }

    pair->ctext = realloc(pair->ctext, encrypted_length);

    return 0;
}

int rsa_decrypt_pair(RSA_key *key, Ptext_ctext_pair* pair) {
    if (change_ctx_decrypt(key) != 0) {
        return -1;
    }

    if (!pair->ctext) {
        return -1;
    }
    if (pair->ptext) {
        free(pair->ptext);
    }

    size_t decrypted_length;
    pair->ptext = malloc(EVP_PKEY_get_size(key->privatekey) + 1);

    if (EVP_PKEY_decrypt(key->ctx, pair->ptext, &decrypted_length, pair->ctext, EVP_PKEY_get_size(key->privatekey)) <= 0) {
        return -1;
    }

    pair->ptext[decrypted_length] = '\0';  // Null-terminate the decrypted text

    return 0;
}


int main(void) {
    RSA_key* key = init_rsa_key("private_key.pem", "public_key.pem");
    Ptext_ctext_pair* encryptedpair = init_rsa_pair();

    unsigned char data[] = "Hello, this is a test message!";
    
    encryptedpair->ptext = malloc(strlen((char * ) data) + 1);
    strcpy((char*)encryptedpair->ptext, (char* )data);

    rsa_encrypt_pair(key, encryptedpair);

    Ptext_ctext_pair* decryptedpair = init_rsa_pair();
    decryptedpair->ctext = malloc(EVP_PKEY_get_size(key->publickey)); 
    memcpy(decryptedpair->ctext, encryptedpair->ctext, EVP_PKEY_get_size(key->publickey)); 


    rsa_decrypt_pair(key, decryptedpair);

    printf("Decrypted Text: %s\n", decryptedpair->ptext);

    
    free_rsa_key(key);
    free_rsa_pair(decryptedpair);
    free_rsa_pair(encryptedpair);
    
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