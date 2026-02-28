#include <stdio.h>
#include <string.h>
#include <argon2.h>
#include <sys/random.h>

uint8_t ITERATIONS = 3;
uint32_t MEMORY = 65536;
uint8_t PARALLELISM = 4;

#define SALTLEN 16
#define HASHLEN 32
#define ENCODED_LEN 128
#define MAX_PW_LEN 64

int hashPassword(const char *password){
    uint8_t salt[SALTLEN];
    uint8_t result = getrandom(salt, SALTLEN, 0);

    if (result < 1){
        perror("random salt generation failed");
        return 1;
    }
    char hashedPassword[HASHLEN];
    char argonString[ENCODED_LEN];
    result = argon2id_hash_encoded(ITERATIONS,MEMORY,PARALLELISM,password,strlen(password),salt,SALTLEN,HASHLEN,argonString,ENCODED_LEN);
    
    if (result != ARGON2_OK){
        printf("hashing did not work: %s\n", argon2_error_message(result));
        return 1;
    }

    printf("Your encrypted password: %s", argonString);
    return 0;
}


int main(){
    char password[MAX_PW_LEN];
    printf("Please enter your password: ");
    if (fgets(password, MAX_PW_LEN,stdin) == NULL){
        printf("Smth failed.");
        return 1;
    };

    password[strcspn(password, "\n")] = 0;      // null-terminator

    hashPassword(password);
    memset(password,0,strlen(password));        // delete the password from RAM
    return 0;
}