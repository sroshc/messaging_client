#ifndef HASH_H
#define HASH_H


#define SESSION_KEY_LENGTH 32


typedef struct Session{
    int user_id;
    char key[256];
    UT_hash_handle hh;
}Session;

char* get_new_session_key(int len);

void init_session_keys();

void free_session_keys();

void add_session(int user_id, char* key);


/* Returns -1 if the key isn't valid, 
    If it is, it will return the user id
*/
int is_key_valid(const char* key);

void delete_session(const char* key);

void print_all_keys();

#endif