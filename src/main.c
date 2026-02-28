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

int hashMasterPassword(const char *password){
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

int verifyMasterPassword(const char *argonString, const char *password){
    int result = argon2id_verify(argonString,password,strlen(password));
    if (result != 0){
        printf("Master Passwort Verification failed: %s\n", argon2_error_message(result));
        return 1;
    }
}

int main(){
    char option[1] = {1};             // 1 = hash your Masterpassword, 2 = verify Masterpassword
    printf("Do you want to...\n \
        \t1: get an Argon2 string for a password?\n \
        \t2: verify if your Masterpassword matches your Argon2 string?\n");
    if (fgets(option,0,stdin) == NULL){
        printf("Something went wrong.");
    }
    char password[MAX_PW_LEN];
    switch (option[0]){
        case 1:

        printf("Please enter your password: \n");
            if (fgets(password, MAX_PW_LEN,stdin) == NULL){
                printf("Smth failed.");
                return 1;
            };
            password[strcspn(password, "\n")] = 0;      // null-terminator
            hashMasterPassword(password);
            memset(password,0,strlen(password));        // delete the password from RAM
            return 0;
        case 2:
            
            char argonString[ENCODED_LEN];

            printf("Enter your password: \n");
            if (fgets(password,0,stdin) == NULL){
                printf("Something went wrong.");
            }
            password[strcspn(password, "\n")] = 0;


            printf("Enter your Argon2ID string: \n");
            if (fgets(argonString,0,stdin) == NULL){
                printf("Something went wrong.");
                // return 1;
            }
            argonString[strcspn(argonString, "\n")] = 0;

            if (password == argonString){
                printf("Success!");
                return 0;
            }
            else{
                printf("Not the same password");
                return 0;
            }
    }
    
    
    

}