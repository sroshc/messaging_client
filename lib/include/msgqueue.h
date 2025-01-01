#ifndef MSGQUEUE_H
#define MSGQUEUE_H

#define MAX_CLIENTS 100

#define CLIENT_LIST_SUCCESS -1
#define CLIENT_LIST_FAILED -2
#define CLIENT_LIST_FULL -3
#define CLIENT_LIST_NOT_CONNECTED -4


int init_global_client_list();

int add_client(pthread_t ct, int cf);

int clear_message_queue(int index);  // No mutex lock, should only be used on active indexes, its fine not to use a mutex

int update_user_id(int index, int user_id);

int update_client_thread(int index, pthread_t ct);

int queue_message(json_object* j_msg, int user_id);

int remove_client(int index);

int send_message_queue(SSL* ssl, int index);

int close_clients();

#endif