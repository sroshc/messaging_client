#include <stdio.h>
#include <stdbool.h>
#include <openssl/ssl.h>
#include <dirent.h>

int doesfileexist(char* filename){
    DIR *dir;
    struct dirent *entry;

    dir = opendir(".");
    if(dir == NULL){
        perror("opendir");
        return -1;
    }

    while((entry = readdir(dir)) != NULL){
        if(strcmp(filename, entry->d_name) == 0){
            closedir(dir);
            return 1;
        }
    }

    closedir(dir);
    return 0;

}

int are_files_valid(char *crtfile, char *keyfile){
	if(!doesfileexist(crtfile)){
		return false;
	}
	if(!doesfileexist(keyfile)){
		return false;
	}
	
	SSL_CTX *ctx;
	ctx = SSL_CTX_new(TLS_server_method());

	if(SSL_CTX_use_certificate_file(ctx, crtfile, SSL_FILETYPE_PEM) <= 0){
		SSL_CTX_free(ctx);
		return false;
	}	

	if(SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM) <= 0){
		SSL_CTX_free(ctx);
		return false;
	}



	if(SSL_CTX_check_private_key(ctx)){
        return true;	

	}else{
		return false;

	}

	SSL_CTX_free(ctx);

}

int main(int argc, char *argv[]){
	char *crtfile;
	char *keyfile; 

	if(argc >= 3){
		crtfile = argv[1];
		keyfile = argv[2];
	}else{
		printf("Invalid arguements\n");
		return -1;
	}
	
	if(!doesfileexist(crtfile)){
		printf("Certificate file does not exist\n");
		return -1;
	}
	if(!doesfileexist(keyfile)){
		printf("Key file does not exist\n");
		return -1;
	}

	printf("Certification file: %s\nKey file: %s\n", crtfile, keyfile);
	
	SSL_CTX *ctx;
	ctx = SSL_CTX_new(TLS_server_method());

	if(SSL_CTX_use_certificate_file(ctx, crtfile, SSL_FILETYPE_PEM) <= 0){
		printf("Invalid certificate file\n");
		SSL_CTX_free(ctx);
		return -1;
	}	

	if(SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM) <= 0){
		printf("Invalid private key\n");
		SSL_CTX_free(ctx);
		return -1;
	}



	if(SSL_CTX_check_private_key(ctx)){
		printf("Private key matches certificate\n");
		if(are_files_valid(crtfile, keyfile)){
			printf("Boolean check function works\n");
		}else{
			printf("Boolean check function does not work\n");
		}
	
	}else{
		printf("Private key does not match certificate\n");
		if(!are_files_valid(crtfile, keyfile)){
			printf("Boolean check function works\n");
		}else{
			printf("Boolean check function does not work\n");
		}
	}


	SSL_CTX_free(ctx);

	
	return 0;

}
