#include <stdio.h>
#include <sqlite3.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include <stdbool.h>
#include <pthread.h>
#include "../include/userdb.h"

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

pthread_mutex_t g_db_mutex = PTHREAD_MUTEX_INITIALIZER;

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
    pthread_mutex_lock(&g_db_mutex);


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
        pthread_mutex_unlock(&g_db_mutex);
        return FAIL;
    }
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, salt, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, final_hash, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);

    if (rc != SQLITE_DONE) {
        fprintf(stderr, "SQL error while adding new user: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        pthread_mutex_unlock(&g_db_mutex);
        return FAIL;
    }
    sqlite3_finalize(stmt);


    //sqlite3_free(zErrMsg);
    free(salt);
    free(final_hash);
    free(binary_hash);
    free(salt_and_pass);

    pthread_mutex_unlock(&g_db_mutex);
    return SUCCESS;
}

int is_user_valid(sqlite3* db, char* username, char* password) {
    sqlite3_stmt *stmtpass = NULL;
    sqlite3_stmt *stmtsalt = NULL;
    int result = VALIDATION_ERROR;
    char *input_salt_and_pass = NULL;
    unsigned char *input_hash = NULL;
    char *final_input_hash = NULL;
    

    const char *sqlpass = "SELECT PASSWORD_HASH FROM USERS WHERE USERNAME = ?;";
    const char *sqlsalt = "SELECT PASSWORD_SALT FROM USERS WHERE USERNAME = ?;";


    if (sqlite3_prepare_v2(db, sqlpass, -1, &stmtpass, 0) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement for hashed password: %s\n", sqlite3_errmsg(db));
        goto cleanup;
    }

    sqlite3_bind_text(stmtpass, 1, username, -1, SQLITE_STATIC);
    int rcpass = sqlite3_step(stmtpass);

    if (rcpass == SQLITE_DONE) {  
        result = USER_DOESNT_EXIST;
        goto cleanup;
    }

    if (rcpass != SQLITE_ROW) {
        fprintf(stderr, "Failed sqlite3_step() for rcpass: %s\n", sqlite3_errmsg(db));
        goto cleanup;
    }

    const char *actual_pass = (const char *)sqlite3_column_text(stmtpass, 0);

    if (sqlite3_prepare_v2(db, sqlsalt, -1, &stmtsalt, 0) != SQLITE_OK) {
        goto cleanup;
    }

    sqlite3_bind_text(stmtsalt, 1, username, -1, SQLITE_STATIC);
    int rcsalt = sqlite3_step(stmtsalt);

    if (rcsalt != SQLITE_ROW){
        fprintf(stderr, "Failed sqlite3_step() for rcsalt: %s\n", sqlite3_errmsg(db));
        goto cleanup;
    }

    const char *actual_salt = (const char *)sqlite3_column_text(stmtsalt, 0);

    size_t input_salt_and_pass_len = strlen(actual_salt) + strlen(password) + 1;
    input_salt_and_pass = malloc(input_salt_and_pass_len);
    if (!input_salt_and_pass) goto cleanup;
    
    snprintf(input_salt_and_pass, input_salt_and_pass_len, "%s%s", actual_salt, password);

    unsigned int input_hash_len = 0;
    digest_message((unsigned char *)input_salt_and_pass, strlen(input_salt_and_pass), 
                  &input_hash, &input_hash_len);
    if (!input_hash) goto cleanup;

    size_t final_input_hash_len = 0;
    final_input_hash = base64_encode(input_hash, input_hash_len, &final_input_hash_len);
    if (!final_input_hash) goto cleanup;

    result = strcmp(final_input_hash, actual_pass) == 0 ? USER_VALID : USER_INVALD;

cleanup:
    if (stmtpass) sqlite3_finalize(stmtpass);
    if (stmtsalt) sqlite3_finalize(stmtsalt);
    free(input_salt_and_pass);
    free(input_hash);
    free(final_input_hash);
    return result;
}

int get_messages(sqlite3* db, int user1_id, int user2_id, char*** messages, int* message_count) {
    const char* sql = 
        "SELECT CONTENT FROM MESSAGES "
        "WHERE (SENDER_ID = ? AND RECEIVER_ID = ?) "
        "   OR (SENDER_ID = ? AND RECEIVER_ID = ?) "
        "ORDER BY TIMESTAMP ASC";

    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement in get_messages: %s\n", sqlite3_errmsg(db));
        return FAIL;
    }

    sqlite3_bind_int(stmt, 1, user1_id);
    sqlite3_bind_int(stmt, 2, user2_id);
    sqlite3_bind_int(stmt, 3, user2_id);
    sqlite3_bind_int(stmt, 4, user1_id);

    char** temp_messages = NULL;
    int count = 0;

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        const char* message = (const char*)sqlite3_column_text(stmt, 0);
        if (!message) continue;

        char* new_message = strdup(message);
        if (!new_message) {
            fprintf(stderr, "Memory allocation failed in get_messages\n");
            rc = FAIL;

            goto cleanup;
        }

        char** resized = realloc(temp_messages, (count + 1) * sizeof(char*));
        if (!resized) {
            fprintf(stderr, "Memory reallocation failed in get_messages\n");
            free(new_message);
            rc = FAIL;

            goto cleanup;
        }

        temp_messages = resized;
        temp_messages[count++] = new_message;
    }

    if (rc != SQLITE_DONE) {
        fprintf(stderr, "SQL error in get_messages: %s\n", sqlite3_errmsg(db));
        rc = FAIL;

        goto cleanup;
    }

    *messages = temp_messages;
    *message_count = count;
    sqlite3_finalize(stmt);
    return SUCCESS;

cleanup:
    for (int i = 0; i < count; ++i) {
        free(temp_messages[i]);
    }


    free(temp_messages);
    *messages = NULL;
    *message_count = 0;
    sqlite3_finalize(stmt);
    return rc;
}

void free_messages(char** messages, int message_count) {
    if (messages == NULL) {
        return;
    }

    for (int i = 0; i < message_count; i++) {
        free(messages[i]); 
    }
    free(messages);
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

int get_user_id(sqlite3* db, char* username){
    const char* sql = "SELECT ID FROM USERS WHERE USERNAME = ?";
    sqlite3_stmt *stmt;
    int rc;

    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);

    if(rc != SQLITE_OK){
        fprintf(stderr, "Failed perparing SQL statement for get_user_id(): %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return -1;
    }

    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);

    if(rc == SQLITE_DONE){
        sqlite3_finalize(stmt);
        return -1;
    }
    
    if(rc != SQLITE_ROW){
        fprintf(stderr, "Failed sqlite3_step() in get_user_id(): %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return -1;
    }

    int res = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    
    return res;
}

int add_message(sqlite3 *db, int sender_id, int receiver_id, char *text){
    const char *sql = "INSERT INTO MESSAGES (SENDER_ID, RECEIVER_ID, CONTENT) VALUES (?, ?, ?)";
    sqlite3_stmt* stmt;
    int rc;
    pthread_mutex_lock(&g_db_mutex);

    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);

    if(rc != SQLITE_OK){
        fprintf(stderr, "Failed preparing SQL statement for add_message(): %s\n", sqlite3_errmsg(db));
        pthread_mutex_unlock(&g_db_mutex);
        return FAIL;
    }

    sqlite3_bind_int(stmt, 1, sender_id);
    sqlite3_bind_int(stmt, 2, receiver_id);
    sqlite3_bind_text(stmt, 3, text, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);

    if(rc == INVALID_MESSAGE){
        sqlite3_finalize(stmt);
        pthread_mutex_unlock(&g_db_mutex);
        return FAIL;
    }

    if(rc != SQLITE_OK && rc != NO_ROW_AVAILABLE){
        fprintf(stderr, "Failed sqlite3_step() in add_message(): %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        pthread_mutex_unlock(&g_db_mutex);
        return FAIL;
    }

    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&g_db_mutex);
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

void close_db(sqlite3 *db){
    sqlite3_close(db);
    return;
}

typedef struct user{
    char* username;
    char* password;
    char* db_path;
}User_ttest;

void* add_user_thread(void* user){
    User_ttest* userlocal = (User_ttest*)user;

    sqlite3* db;
    if (sqlite3_open(userlocal->db_path, &db) != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        return NULL;
    }

    char curr_username[50];
    for (int i = 0; i < 100; i++) {
        memset(curr_username, 0, sizeof(curr_username));
        sprintf(curr_username, "%s%d", userlocal->username, i);
        add_user(db, curr_username, userlocal->password);
    }

    sqlite3_close(db);

    return NULL;
}

void* check_user_thread(void* user){
    User_ttest* userlocal = (User_ttest*)user;

    sqlite3* db;
    if (sqlite3_open(userlocal->db_path, &db) != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        return NULL;
    }

    char curr_username[50];
    for (int i = 0; i < 100; i++) {
        memset(curr_username, 0, sizeof(curr_username));
        sprintf(curr_username, "%s%d", userlocal->username, i);
        if(is_user_valid(db, curr_username, userlocal->password) == USER_VALID){
            printf("Valid: %s%d\n", userlocal->username,i);
        }else{
            printf("Invalid: %s%d\n", userlocal->username,i);

        }
    }

    sqlite3_close(db);

    return NULL;
}
void test_multi_threading(){
    const char *db_name = "temp_db"; 
    pthread_t thread1, thread2;

    create_database((char *)db_name);

    User_ttest* user1 = malloc(sizeof(User_ttest));
    user1->username = strdup("t1user");
    user1->password = strdup("supersecretpassword");
    user1->db_path = strdup(db_name);

    User_ttest* user2 = malloc(sizeof(User_ttest));
    user2->username = strdup("t2user");
    user2->password = strdup("supersecretpassword");
    user2->db_path = strdup(db_name);

    pthread_create(&thread1, NULL, add_user_thread, user1);
    pthread_create(&thread2, NULL, add_user_thread, user2);

    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);

    pthread_t check_thread1, check_thread2;

    pthread_create(&check_thread1, NULL, check_user_thread, user1);
    pthread_create(&check_thread2, NULL, check_user_thread, user2);


    pthread_join(check_thread1, NULL);
    pthread_join(check_thread2, NULL);

    free(user1->username);
    free(user1->password);
    free(user1->db_path);
    free(user2->username);
    free(user2->password);
    free(user2->db_path);

    if(remove(db_name) != 0){
        printf("Failed to remove %s\n.", db_name);
    }

    return;
}

int main(){
    sqlite3* db = create_database("db");
    
    add_user(db, "user1", "pass1");
    add_user(db, "user2", "pass2");
    add_user(db, "user3", "pass3");

    add_message(db, get_user_id(db, "user1"), get_user_id(db, "user2"), "heyyyyyyyyyyyyy");
    add_message(db, get_user_id(db, "user2"), get_user_id(db, "user1"), "heyyyyyyyyyy");
    add_message(db, get_user_id(db, "user1"), get_user_id(db, "user2"), "heyyyyyyyy");
    add_message(db, get_user_id(db, "user2"), get_user_id(db, "user1"), "heyyyyyy");
    add_message(db, get_user_id(db, "user1"), get_user_id(db, "user2"), "heyyy");
    add_message(db, get_user_id(db, "user2"), get_user_id(db, "user1"), "heyy");

    print_all(db, "MESSAGES");

    char** messages;
    int messages_num;


    get_messages(db, 1, 2, &messages, &messages_num);

    for(int i = 0; i < messages_num; i++){
        printf("%s\n", messages[i]);
    }

    free_messages(messages, messages_num);

    printf("Messages number: %d\n", messages_num);


    test_multi_threading();

    return 0;
}


