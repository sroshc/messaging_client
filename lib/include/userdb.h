#ifndef USERDB_H
#define USERDB_H

#define DB_USER_VALID 1
#define DB_USER_INVALD 0
#define DB_USER_DOESNT_EXIST -1
#define DB_VALIDATION_ERROR -2
#define DB_SUCCESS 1
#define DB_FAIL 0

#define NO_ROW_AVAILABLE 101
#define INVALID_MESSAGE 19

#define SALTLENGTH 16
#define HASHLENGTH 32
#define SALT_BASE64_LENGTH 25

sqlite3 *create_database(char* name);

int add_user(sqlite3 *db, char *username, char *password);

int is_user_valid(sqlite3* db, char* username, char* password);

bool does_user_exist(sqlite3 *db, char* username);

int get_user_id(sqlite3* db, char* username);

int add_message(sqlite3 *db, int sender_id, int receiver_id, char *text);

int get_messages_json(sqlite3* db, int user1_id, int user2_id, json_object** res, int* message_count);

int print_all(sqlite3 *db, char* table);

void close_db(sqlite3 *db);

#endif