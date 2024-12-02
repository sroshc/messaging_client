#include "uthash.h"
#include <stdio.h>
#include <stdbool.h>
#include <pthread.h>
#include <openssl/rand.h>
#include "../include/encode.h"
#include "../include/hash.h"

Session *session= NULL;
pthread_mutex_t lock;

void init_session_keys(){
    if(pthread_mutex_init(&lock, NULL) != 0){
        fprintf(stderr, "Error while creating mutex for session keys hash table");
    }

    return;
}

void free_session_keys(){
    if(!session){
        return;
    }

    Session *curr_session, *tmp;

    HASH_ITER(hh, session, curr_session, tmp) {
        HASH_DEL(session, curr_session); 
        free(curr_session);
    }

    pthread_mutex_destroy(&lock);

    return;
}


void add_session(int user_id, char* key){
    Session *s = malloc(sizeof(Session));
    s->user_id = user_id;
    strncpy(s->key, key, SESSION_KEY_LENGTH);
    HASH_ADD_INT(session, user_id, s);
    return;
}

bool is_key_valid(int id, const char* key){
    Session* s;
    HASH_FIND_INT(session, &id, s);
    if(!s){
        return NULL;
    }

    return strcmp(s->key, key) == 0;
}

void delete_session(int id){
    Session* s;
    HASH_FIND_INT(session, &id, s);

    if(s){
        HASH_DEL(session, s);
        free(s);
    }

    return;
}

char* get_new_session_key(int len){
    int rand_len = (len/4 * 3); 

    unsigned char u_res[rand_len];
    RAND_bytes(u_res, rand_len);

    size_t output_length;
    char* res = base64_encode((const unsigned char*) u_res, rand_len, &output_length);
    
    return res;
}

void test_hash_table(){
    init_session_keys();

    add_session(1, "hello");
    add_session(2, "hi");

    if(is_key_valid(1, "hello") && !is_key_valid(1, "dsajd") && is_key_valid(2, "hi") && !is_key_valid(3, "hi")){
        printf("Works!\n");
    }else{
        printf("Doesn't work.\n");
    }

    free_session_keys();
}
