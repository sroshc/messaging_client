#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdio.h>

typedef struct Sym_key{
    unsigned char key[256];
    unsigned char iv[128];

}Sym_key;

Sym_key* init_key(){
    Sym_key *k = malloc(sizeof(Sym_key));
    RAND_bytes(k->key, 256);
    RAND_bytes(k->iv, 128);

    return k;
} 

void handleErrors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int _sym_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
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

int _sym_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
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




int main (void)
{
    Sym_key* key = init_key();
    int ciphertext_len;

    unsigned char* ciphertext = sym_encrypt(key, "The quick brown fox jumps over the lazy dog.", &ciphertext_len);
    char* decryptedtext = sym_decrypt(key, ciphertext, ciphertext_len);
    printf("%s\n", decryptedtext);

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
}

