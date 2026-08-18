#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sodium.h>
#include <openssl/evp.h>
#include "Cryptxor.h"

int main(void) {
    if (sodium_init() != 0) {
        printf("Libsodium initialization error!\n");
        exit(EXIT_FAILURE);
    }
    char file_name[FILENAME_LEN];
    unsigned char buffer_file[BUFFER_LEN];
    Choice choice = EXIT;
    bool success = false;
    char password[PASSWORD_LEN];
    char* pointer = NULL;
    do {
        print_banner();
        print_menu();
        do {
            scanf("%d",&choice);
            getchar();
            if (choice < EXIT || choice > AES_DECRYPT) {
                printf("Insert a valid choice: ");
            }
        }while (choice < EXIT || choice > AES_DECRYPT);
        switch (choice) {
            case EXIT:
                printf("Goodbye!");
                break;
            case XOR_ENCRYPT:
                do {
                    printf("Insert file name/path: ");
                    fgets(file_name,FILENAME_LEN,stdin);
                    file_name[strcspn(file_name, "\n")] = '\0';
                    if (strlen(file_name) >= FILENAME_LEN - 5) {
                        printf("Path or file name too long!\n");
                    }
                }while (strlen(file_name) >= FILENAME_LEN - 5);
                do {
                    printf("Insert password: ");
                    fgets(password,PASSWORD_LEN,stdin);
                    password[strcspn(password, "\n")] = '\0';
                    if (strlen(password) == 0) {
                        printf("Password cannot be empty!\n");
                    }
                    else if (strlen(password) > PASSWORD_LEN) {
                        printf("Password too long!\n");
                    }
                }while (strlen(password) == 0 || strlen(password) > PASSWORD_LEN);
                success = xor_encryption(buffer_file,file_name,password);
                if (success) {
                    printf("File encrypted successfully!\n\n");
                }
                break;
            case XOR_DECRYPT:
                do {
                    printf("Insert file name/path(.enc format): ");
                    fgets(file_name,FILENAME_LEN,stdin);
                    file_name[strcspn(file_name, "\n")] = '\0';
                    pointer = strrchr(file_name,'.');
                    if (pointer == NULL || strcmp(pointer,".enc") != 0) {
                        printf("The selected file is not .enc!\n");
                    }
                    else if (strlen(file_name) >= FILENAME_LEN - 5) {
                        printf("Path or file name too long!\n");
                    }
                }while(pointer == NULL || strcmp(pointer,".enc") != 0 || strlen(file_name) >= FILENAME_LEN - 5);
                do {
                    printf("Insert password: ");
                    fgets(password,PASSWORD_LEN,stdin);
                    password[strcspn(password, "\n")] = '\0';
                    if (strlen(password) == 0) {
                        printf("Password cannot be empty!\n");
                    }
                    else if (strlen(password) > PASSWORD_LEN) {
                        printf("Password too long!\n");
                    }
                }while (strlen(password) == 0 || strlen(password) > PASSWORD_LEN);
                success = xor_decryption(buffer_file,file_name,password);
                if (success) {
                    printf("File decrypted successfully!\n\n");
                }
                break;
            case AES_ENCRYPT:
                do {
                    printf("Insert file name/path: ");
                    fgets(file_name,FILENAME_LEN,stdin);
                    file_name[strcspn(file_name, "\n")] = '\0';
                    if (strlen(file_name) >= FILENAME_LEN - 5) {
                        printf("Path or file name too long!\n");
                    }
                }while (strlen(file_name) >= FILENAME_LEN - 5);
                do {
                    printf("Insert password: ");
                    fgets(password,PASSWORD_LEN,stdin);
                    password[strcspn(password, "\n")] = '\0';
                    if (strlen(password) == 0) {
                        printf("Password cannot be empty!\n");
                    }
                    else if (strlen(password) > PASSWORD_LEN) {
                        printf("Password too long!\n");
                    }
                }while (strlen(password) == 0 || strlen(password) > PASSWORD_LEN);
                success = aes256_encryption(buffer_file,file_name,password);
                if (success) {
                    printf("File encrypted successfully!\n\n");
                }
                break;
            case AES_DECRYPT:
                do {
                    printf("Insert file name/path(.enc format): ");
                    fgets(file_name,FILENAME_LEN,stdin);
                    file_name[strcspn(file_name, "\n")] = '\0';
                    pointer = strrchr(file_name,'.');
                    if (pointer == NULL || strcmp(pointer,".enc") != 0) {
                        printf("The selected file is not .enc!\n");
                    }
                    else if (strlen(file_name) >= FILENAME_LEN - 5) {
                        printf("Path or file name too long!\n");
                    }
                }while(pointer == NULL || strcmp(pointer,".enc") != 0 || strlen(file_name) >= FILENAME_LEN - 5);
                do {
                    printf("Insert password: ");
                    fgets(password,PASSWORD_LEN,stdin);
                    password[strcspn(password, "\n")] = '\0';
                    if (strlen(password) == 0) {
                        printf("Password cannot be empty!\n");
                    }
                    else if (strlen(password) > PASSWORD_LEN) {
                        printf("Password too long!\n");
                    }
                }while (strlen(password) == 0 || strlen(password) > PASSWORD_LEN);
                success = aes256_decryption(buffer_file,file_name,password);
                if (success) {
                    printf("File decrypted successfully!\n\n");
                }
                break;
            default:
                break;
        }
    }while (choice != EXIT);
    exit(EXIT_SUCCESS);
}
