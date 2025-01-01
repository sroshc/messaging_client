#include <openssl/ssl.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <json-c/json.h>
#include <pthread.h>

#include "../include/msgqueue.h"


/*
{
    is_message = 1,
    message[
        content: "blahblahblah",
        from_id: 2,
        from_user: sroshc
    ]
}
*/


pthread_mutex_t client_lock = PTHREAD_MUTEX_INITIALIZER;

typedef struct Message{
    json_object* message;
    struct Message* next;
}Message;

typedef struct Client{
    pthread_t client_thread;
    int client_fd;
    int user_id;
    Message *message_queue;
    bool is_active;
}Client;

Client global_clients[MAX_CLIENTS];

int init_global_client_list(){
    for(int i = 0; i < MAX_CLIENTS; i++){
        global_clients[i].client_thread = -1;
        global_clients[i].client_fd = -1;
        global_clients[i].user_id = -1;
        global_clients[i].message_queue = NULL;
        global_clients[i].is_active = false;
    }

    return CLIENT_LIST_SUCCESS;
}


int add_client(pthread_t ct, int cf){
    int index = -1;

    pthread_mutex_lock(&client_lock);
    for(int i = 0; i < MAX_CLIENTS; i++){
        if(global_clients[i].is_active == false){
            index = i;
            global_clients[i].client_thread = ct;
            global_clients[i].client_fd = cf;
            global_clients[i].message_queue = NULL;
            global_clients[i].is_active = true;
            break;
        }
    } 
    pthread_mutex_unlock(&client_lock);

    return index == -1 ? CLIENT_LIST_FULL: index; 
}

int clear_message_queue(int index){  // No mutex lock, should only be used on active indexes, its fine not to use a mutex
    Message* mp = global_clients[index].message_queue;
    Message* previous_mp;

    while(mp != NULL){
        previous_mp = mp;
        mp = mp->next;

        json_object_put(previous_mp->message);
        free(previous_mp);
    }

    global_clients[index].message_queue = NULL;

    return CLIENT_LIST_SUCCESS;
}

int update_user_id(int index, int user_id){
    if(index >= MAX_CLIENTS || index < 0){
        return CLIENT_LIST_FAILED;
    }else{
        pthread_mutex_lock(&client_lock);
        global_clients[index].user_id = user_id;
        clear_message_queue(index);
        pthread_mutex_unlock(&client_lock);
        
    }

    return CLIENT_LIST_SUCCESS;
}

int update_client_thread(int index, pthread_t ct){
    if(index >= MAX_CLIENTS || index < 0){
        return CLIENT_LIST_FAILED;
    }else{
        pthread_mutex_lock(&client_lock);
        global_clients[index].client_thread = ct;
        //clear_message_queue(index);
        pthread_mutex_unlock(&client_lock);
        
    }

    return CLIENT_LIST_SUCCESS;
}
int queue_message(json_object* j_msg, int user_id){
    int index = -1;
    
    pthread_mutex_lock(&client_lock);

    for(int i = 0; i < MAX_CLIENTS; i++){
        if(global_clients[i].user_id == user_id){
            index = i;
            break;
        }
    }

    if(index == -1){
        return CLIENT_LIST_NOT_CONNECTED;
    }

    if(global_clients[index].is_active == false){
        printf("Message Queue Error: Tried to send a message to an inactive thread!\n");
        pthread_mutex_unlock(&client_lock);
        return CLIENT_LIST_FAILED;
    } 

    Message* new_message;
    new_message = malloc(sizeof(Message));
    new_message->next = NULL;
    new_message->message = json_object_get(j_msg);


    if(global_clients[index].message_queue == NULL){
        global_clients[index].message_queue = new_message;
    }else{
        Message* mp;
        for(mp = global_clients[index].message_queue; mp->next != NULL ; mp = mp->next);
        mp->next = new_message;
    }
    pthread_mutex_unlock(&client_lock);

    return CLIENT_LIST_SUCCESS;
}

int remove_client(int index){  
    clear_message_queue(index);

    pthread_mutex_lock(&client_lock);
    global_clients[index].message_queue = NULL;

    global_clients[index].client_fd = -1;
    global_clients[index].client_thread = -1;
    global_clients[index].user_id = -1;
    global_clients[index].is_active = false;

    pthread_mutex_unlock(&client_lock);
    return CLIENT_LIST_SUCCESS;

}

int send_message_queue(SSL* ssl, int index){
    Message* mp = global_clients[index].message_queue;
    
    pthread_mutex_lock(&client_lock);
    while(mp != NULL){
        const char* msg = json_object_to_json_string_ext(mp->message, JSON_C_TO_STRING_NOSLASHESCAPE);
        SSL_write(ssl, msg, strlen(msg));
        mp = mp->next;
    }
    clear_message_queue(index);
    pthread_mutex_unlock(&client_lock);

    return CLIENT_LIST_SUCCESS;

}

int close_clients(){
    pthread_mutex_lock(&client_lock);
    
    for(int i = 0; i < MAX_CLIENTS; i++){
        close(global_clients[i].client_fd);
    }

    pthread_mutex_unlock(&client_lock);

    return CLIENT_LIST_SUCCESS;
}