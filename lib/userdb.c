#include <stdio.h>
#include <sqlite3.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include <stdbool.h>

#define USER_VALID 1
#define USER_INVALD 0
#define USER_DOESNT_EXIST -1
#define VALIDATION_ERROR -2
#define SUCCESS 1
#define FAIL 0

#define NO_ROW_AVAILABLE 101
#define INVALID_MESSAGE 19

#define SALTLENGTH 16
#define HASHLENGTH 32
#define SALT_BASE64_LENGTH 25

void handleErrors(){
    fprintf(stderr, "Panic! Digest message failed\n");
    return;
}

//Old SHA256_Init() was depracated
void digest_message(const unsigned char *message, size_t message_len, unsigned char **digest, unsigned int *digest_len)
{
	EVP_MD_CTX *mdctx;

	if((mdctx = EVP_MD_CTX_new()) == NULL)
		handleErrors();

	if(1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL))
		handleErrors();

	if(1 != EVP_DigestUpdate(mdctx, message, message_len))
		handleErrors();

	if((*digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha256()))) == NULL)
		handleErrors();

	if(1 != EVP_DigestFinal_ex(mdctx, *digest, digest_len))
		handleErrors();

	EVP_MD_CTX_free(mdctx);
}

static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};
static char *decoding_table = NULL;
static int mod_table[] = {0, 2, 1};


char *base64_encode(const unsigned char *data,
                    size_t input_length,
                    size_t *output_length) {

    *output_length = 4 * ((input_length + 2) / 3);

    char *encoded_data = malloc(*output_length);
    if (encoded_data == NULL) return NULL;

    for (int i = 0, j = 0; i < input_length;) {

        uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }

    for (int i = 0; i < mod_table[input_length % 3]; i++)
        encoded_data[*output_length - 1 - i] = '=';

    return encoded_data;
}


void build_decoding_table() {

    decoding_table = malloc(256);

    for (int i = 0; i < 64; i++)
        decoding_table[(unsigned char) encoding_table[i]] = i;
}


unsigned char *base64_decode(const char *data,
                             size_t input_length,
                             size_t *output_length) {

    if (decoding_table == NULL) build_decoding_table();

    if (input_length % 4 != 0) return NULL;

    *output_length = input_length / 4 * 3;
    if (data[input_length - 1] == '=') (*output_length)--;
    if (data[input_length - 2] == '=') (*output_length)--;

    unsigned char *decoded_data = malloc(*output_length);
    if (decoded_data == NULL) return NULL;

    for (int i = 0, j = 0; i < input_length;) {

        uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];

        uint32_t triple = (sextet_a << 3 * 6)
        + (sextet_b << 2 * 6)
        + (sextet_c << 1 * 6)
        + (sextet_d << 0 * 6);

        if (j < *output_length) decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
    }

    return decoded_data;
}

void base64_cleanup() {
    free(decoding_table);
}

static int callback(void *NotUesd, int argc, char **argv, char **azColName){
       int i;
   for(i = 0; i<argc; i++) {
      printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
   }
   printf("\n");
   return 0;
}

sqlite3 *create_database(char* name){
    sqlite3 *db;
    char *zErrMsg = 0;
    int rc;
    char *sql;

    rc = sqlite3_open(name, &db);

    if(rc){
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        return NULL;
    }

    sqlite3_exec(db, "PRAGMA foreign_keys = ON;", NULL, NULL, NULL); // To enable foreign keys or whatever

    sql = "CREATE TABLE IF NOT EXISTS USERS(" \
    "ID INTEGER PRIMARY KEY AUTOINCREMENT, "\
    "USERNAME   TEXT    NOT NULL UNIQUE, "\
    "PASSWORD_SALT TEXT  NOT NULL, "\
    "PASSWORD_HASH TEXT  NOT NULL);";


    rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);
    
    if(rc != SQLITE_OK){
        fprintf(stderr, "SQL error while creating users table: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        sqlite3_close(db);
        return NULL;
    }


    sql = "CREATE INDEX IF NOT EXISTS idx_users_id on USERS(ID);";

    rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);


    if(rc != SQLITE_OK){
        fprintf(stderr, "SQL error while creating index: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        return NULL;
    }

    sql = "CREATE TABLE IF NOT EXISTS MESSAGES(" \
    "ID INTEGER PRIMARY KEY AUTOINCREMENT, "\
    "SENDER_ID INTEGER NOT NULL, "\
    "RECEIVER_ID INTEGER NOT NULL," \
    "CONTENT TEXT NOT NULL," \
    "TIMESTAMP DATETIME DEFAULT CURRENT_TIMESTAMP, "\
    "FOREIGN KEY(SENDER_ID) REFERENCES USERS(ID), " \
    "FOREIGN KEY(RECEIVER_ID) REFERENCES USERS(ID));";
    
    
    rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

    if(rc!= SQLITE_OK){
        fprintf(stderr, "SQL error while creating messages table: %s\n", zErrMsg);
    }


    sqlite3_free(zErrMsg);
    return db;

}


int add_user(sqlite3 *db, char *username, char *password){
    int rc;

    unsigned char binary_salt[SALTLENGTH];
    RAND_bytes(binary_salt, SALTLENGTH);

    size_t encoded_salt_len;    
    char *salt = base64_encode(binary_salt, SALTLENGTH, &encoded_salt_len);

    
    size_t salt_and_pass_len = strlen(salt) + strlen(password) + 1;
    char *salt_and_pass = malloc(salt_and_pass_len);    
    snprintf(salt_and_pass, salt_and_pass_len, "%s%s", salt, password);
    
    
    /* This is depracted, gives me an annoying error :((
    SHA256_CTX sha256_ctx;
    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, salt_and_pass, strlen(salt_and_pass));
    SHA256_Final(binary_hash, &sha256_ctx);
    */

    unsigned char *binary_hash;
    unsigned int binary_hash_len;
    digest_message(salt_and_pass, strlen(salt_and_pass), &binary_hash, &binary_hash_len);

    size_t final_hash_len;
    char *final_hash = base64_encode(binary_hash, binary_hash_len, &final_hash_len);


    const char *sql = "INSERT INTO USERS (USERNAME, PASSWORD_SALT, PASSWORD_HASH) VALUES (?, ?, ?)";
    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement while adding new user: %s\n", sqlite3_errmsg(db));
        free(salt);
        free(final_hash);
        free(binary_hash);
        free(salt_and_pass);
        return FAIL;
    }
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, salt, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, final_hash, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "SQL error while adding new user: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return FAIL;
    }
    sqlite3_finalize(stmt);


    //sqlite3_free(zErrMsg);
    free(salt);
    free(final_hash);
    free(binary_hash);
    free(salt_and_pass);

    return SUCCESS;
}

int is_user_valid(sqlite3* db, char* username, char* password){
    sqlite3_stmt *stmtpass;
    sqlite3_stmt *stmtsalt;
    int rcpass;
    int rcsalt;
    const char *sqlpass = "SELECT PASSWORD_HASH FROM USERS WHERE USERNAME = ?;";
    const char *sqlsalt = "SELECT PASSWORD_SALT FROM USERS WHERE USERNAME = ?;";

    // Querying for the password hash
    rcpass = sqlite3_prepare_v2(db, sqlpass, -1, &stmtpass, 0); 

    if(rcpass != SQLITE_OK){
        fprintf(stderr, "Failed to prepare statement for hashed password while validating login: %s\n", sqlite3_errmsg(db));
        return VALIDATION_ERROR;
    }

    sqlite3_bind_text(stmtpass, 1, username, -1, SQLITE_STATIC);

    rcpass = sqlite3_step(stmtpass);

    if(rcpass == 101){ //Fix this one day
        return USER_DOESNT_EXIST;
    }

    if(rcpass != SQLITE_ROW){
        printf("%d\n", rcpass);
        fprintf(stderr, "Failed sqlite3_step() for rcpass while validating login: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmtpass);
        return VALIDATION_ERROR;
    }

    const char *actual_pass = sqlite3_column_text(stmtpass, 0);


    // Querying for the password salt
    rcsalt = sqlite3_prepare_v2(db, sqlsalt, -1, &stmtsalt, 0);

    if(rcsalt != SQLITE_OK){
        fprintf(stderr, "Failed to prepare statement for salt while validating login: %s\n", sqlite3_errmsg(db));
        return VALIDATION_ERROR;
    }

    sqlite3_bind_text(stmtsalt, 1, username, -1, SQLITE_STATIC);

    rcsalt = sqlite3_step(stmtsalt);
    
    if(rcsalt != SQLITE_ROW){
        fprintf(stderr, "Failed sqlite3_step() for rcsalt while validating login: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmtpass);
        sqlite3_finalize(stmtsalt);
        return VALIDATION_ERROR;
    }

    const char *actual_salt = sqlite3_column_text(stmtsalt, 0);

    // Combine decoded salt with the password
    size_t input_salt_and_pass_len = strlen(actual_salt) + strlen(password) + 1;
    char *input_salt_and_pass = malloc(input_salt_and_pass_len);
    snprintf(input_salt_and_pass, input_salt_and_pass_len, "%s%s", actual_salt, password);

    printf("Concatted pass and salt: %s\n", input_salt_and_pass);


    unsigned char *input_hash;
    unsigned int input_hash_len = 0;
    digest_message(input_salt_and_pass, strlen(input_salt_and_pass), &input_hash, &input_hash_len);


    size_t final_input_hash_len = 0;
    char* final_input_hash = base64_encode(input_hash, input_hash_len, &final_input_hash_len);

    printf("Computed Hash: %s\n", final_input_hash);

    int result = strcmp(final_input_hash, actual_pass) == 0 ? USER_VALID : USER_INVALD;


    // Clean up
    sqlite3_finalize(stmtpass);
    sqlite3_finalize(stmtsalt);
    free(final_input_hash);
    free(input_salt_and_pass);
    free(input_hash);

    return result;
}

bool does_user_exist(sqlite3 *db, char* username){
    const char* sql = "SELECT 1 FROM USERS WHERE USERNAME = ?";
    sqlite3_stmt* stmt;
    int rc;
    
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0); 

    if(rc != SQLITE_OK){
        fprintf(stderr, "Failed preparing SQL statement for does_user_exist(): %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return false;
    }

    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    
    if(rc == NO_ROW_AVAILABLE){
        sqlite3_finalize(stmt);
        return false;
    }

    if(rc != SQLITE_ROW){
        fprintf(stderr, "Failed sqlite3_step() in does_user_exist(): %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return false;
    }

    sqlite3_finalize(stmt);
    return true;

}

int add_message(sqlite3 *db, int sender_id, int receiver_id, char *text){
    const char *sql = "INSERT INTO MESSAGES (SENDER_ID, RECEIVER_ID, CONTENT) VALUES (?, ?, ?)";
    sqlite3_stmt* stmt;
    int rc;

    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);

    if(rc != SQLITE_OK){
        fprintf(stderr, "Failed preparing SQL statement for add_message(): %s\n", sqlite3_errmsg(db));
        return FAIL;
    }

    sqlite3_bind_int(stmt, 1, sender_id);
    sqlite3_bind_int(stmt, 2, receiver_id);
    sqlite3_bind_text(stmt, 3, text, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);

    if(rc == INVALID_MESSAGE){
        sqlite3_finalize(stmt);
        return FAIL;
    }

    if(rc != SQLITE_OK && rc != NO_ROW_AVAILABLE){
        fprintf(stderr, "Failed sqlite3_step() in add_message(): %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return FAIL;
    }

    sqlite3_finalize(stmt);
    return SUCCESS;
}

int print_all(sqlite3 *db, char* table){
    char *zErrMsg;
    int rc;
    char sql[256];
    const char* data = "Callback function called";

    //sql = "SELECT * from MESSAGES";

    snprintf(sql, 255 ,"SELECT * from %s", table);


    rc = sqlite3_exec(db, sql, callback, (void*)data, &zErrMsg);

    if(rc != SQLITE_OK){
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        return 1;
    }

    sqlite3_free(zErrMsg);
    return 0;

}


//void digest_message(const unsigned char *message, size_t message_len, unsigned char **digest, unsigned int *digest_len)

int main(){
    sqlite3* db = create_database("db");

    add_user(db, "user", "pass");
    add_user(db, "user1", "pass1");
    add_user(db, "user2", "pass2");




    print_all(db, "USERS");
    print_all(db, "MESSAGES");

    return 0;
}
