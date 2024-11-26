#ifndef HASH_H
#define HASH_H


#define SESSION_KEY_LENGTH 32


typedef struct Session{
    int user_id;
    char key[SESSION_KEY_LENGTH];
    UT_hash_handle hh;
}Session;

void init_session_keys();

void free_session_keys();

void add_session(int user_id, char* key);

bool is_key_valid(int id, const char* key);

void delete_session(int id);

#endif