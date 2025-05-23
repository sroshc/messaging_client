#ifndef PARSER_H
#define PARSER_H


typedef struct json_object json_object;

#define SESSION_TOKEN "session_token"
#define COMMAND "command"
#define ARGUMENTS "arguments"

#define USERNAME "username"
#define PASSWORD "password"
#define RECIPIENT_ID "recipient_id"
#define SENDER_ID "sender_id"
#define CONTENT "content"
#define OTHER_USER_ID "other_user_id"
#define DATA "data"
#define MESSAGES "messages"

enum response{
    AUTHORIZED = 201,
    NOT_AUTHORIZED = 401,
    BAD_REQUEST = 400,
    SERVER_FAILED = 500,
    SUCCESS = 200
};

enum Command{
    LOGIN,
    MAKE_ACCOUNT,
    SEND_MESSAGE,
    GET_MESSAGES,
    INVALID,
};

/* Returns the command enum, and returns -1 if the json_string is invalid.*/
int get_command_int(const char* string_command);


/* Returns the command enum, and returns -1 if the json_string is invalid. Also dynamicaly stores the new json_object*/
int get_command(char* json_string, json_object** object);

#endif