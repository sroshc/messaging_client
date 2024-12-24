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
    if (!s) {
        fprintf(stderr, "Memory allocation failed\n");
        return;
    }
    s->user_id = user_id;
    strncpy(s->key, key, SESSION_KEY_LENGTH); 
    HASH_ADD_STR(session, key, s);           
    return;
}


int is_key_valid(const char* key) {
    Session* s;
    HASH_FIND_STR(session, key, s);
    return s == NULL ? -1: s->user_id;
}

void delete_session(const char* key) {
    Session* s;
    HASH_FIND_STR(session, key, s);
    if (s) {
        HASH_DEL(session, s);
        free(s);
    }
}


char* get_new_session_key(int len){
    int rand_len = (len * 3 ) / 4; 

    unsigned char u_res[rand_len];
    RAND_bytes(u_res, rand_len);

    size_t output_length;
    char* res = base64_encode((const unsigned char*) u_res, rand_len, &output_length);
    
    if(output_length != len){
        printf("Function get_new_session_key() doesn't return the correct length\n");
    }

    return res;
}

void print_all_keys(){
    if(!session){
        return;
    }

    Session *curr_session, *tmp;

    HASH_ITER(hh, session, curr_session, tmp) {
        printf("ID: %d, KEY: %s\n", curr_session->user_id, curr_session->key);
    }


    return;
}

void test_hash_table(){
    init_session_keys();

    add_session(1, "hello");
    add_session(2, "hi");

    if(is_key_valid("hello") && !is_key_valid("dsajd") && is_key_valid("hi") && !is_key_valid("hsi")){
        printf("Works!\n");
    }else{
        printf("Doesn't work.\n");
    }

    free_session_keys();
}
