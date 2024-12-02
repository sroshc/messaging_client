#include <json-c/json.h>
#include <stdio.h>
#include <string.h>
#include "../include/parser.h"


const char* commands[] = {"LOGIN", "MAKE_ACCOUNT", "SEND_MESSAGE"};

int get_command_int(const char* string_command){
    if(string_command == NULL){
        return -1;
    }

    size_t size = sizeof(commands) / sizeof(commands[0]);

    for(int i = 0; i < size; i++ ){
        if(strcmp(string_command, commands[i]) == 0){
            return i;
        }
    }

    return -1;
}

int get_command(char* json_string, json_object** object){
    *object = json_tokener_parse(json_string);

    if(object == NULL){
        return INVALID;
    }

    json_object *json_command;
    json_object_object_get_ex(*object, COMMAND, &json_command);

    if(json_command == NULL){
        json_object_put(*object);
        return INVALID;
    }

    int command_int = get_command_int(json_object_get_string(json_command));


    return command_int == -1 ? INVALID : command_int;
}


void test(){
    char* json_string = "{ \"command\": \"MAKE_ACCOUNT\" }";

    json_object *object;

    int x = get_command(json_string, & object);

    if(x == MAKE_ACCOUNT){
        printf("Success\n");
    }
    printf("%d\n", x);

    json_object_put(object);
}
