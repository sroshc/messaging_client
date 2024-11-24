#ifndef USERDB_H
#define USERDB_H

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


char *base64_encode(const unsigned char *data, size_t input_length, size_t *output_length);

void build_decoding_table();

unsigned char *base64_decode(const char *data, size_t input_length, size_t *output_length);

void base64_cleanup();

sqlite3 *create_database(char* name);

int add_user(sqlite3 *db, char *username, char *password);

int is_user_valid(sqlite3* db, char* username, char* password);

bool does_user_exist(sqlite3 *db, char* username);

int add_message(sqlite3 *db, int sender_id, int receiver_id, char *text);

int print_all(sqlite3 *db, char* table);

void close_db(sqlite3 *db);

#endif