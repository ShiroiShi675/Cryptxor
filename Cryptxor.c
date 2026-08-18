#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <sodium.h>
#include <openssl/evp.h>
#include "Cryptxor.h"

bool xor_encryption(unsigned char* buffer_file,const char* file_name,const char* password) {
    FILE* f_input = NULL;
    FILE* f_output = NULL;
    int j = 0;
    char file_name_output[FILENAME_LEN];
    strcpy(file_name_output,file_name);
    int password_length = (int)strlen(password);
    size_t bytes_read;
    f_input = fopen(file_name,"rb");
    if (!check_file(f_input)) {
        return false;
    }
    f_output = fopen(strcat(file_name_output,".enc"),"wb");
    if (!check_file(f_output)) {
        fclose(f_input);
        return false;
    }
    while ((bytes_read = fread(buffer_file,1,BUFFER_LEN,f_input)) > 0) {
        for (size_t i = 0;i < bytes_read;i++) {
            buffer_file[i] ^= password[j];
            j++;
            if (j == password_length) {
                j = 0;
            }
        }
        fwrite(buffer_file,1,bytes_read,f_output);
    }
    fclose(f_input);
    fclose(f_output);
    return true;
}

bool xor_decryption(unsigned char* buffer_file,const char* file_name,const char* password) {
    FILE* f_input = NULL;
    FILE* f_output = NULL;
    int j = 0;
    int password_length = (int)strlen(password);
    char file_name_output[FILENAME_LEN];
    strcpy(file_name_output,file_name);
    char* point = strrchr(file_name_output,'.');
    *point = '\0';
    size_t bytes_read;
    f_input = fopen(file_name,"rb");
    if (!check_file(f_input)) {
        return false;
    }
    f_output = fopen(file_name_output,"wb");
    if (!check_file(f_output)) {
        fclose(f_input);
        return false;
    }
    while ((bytes_read = fread(buffer_file,1,BUFFER_LEN,f_input)) > 0) {
        for (size_t i = 0;i < bytes_read;i++) {
            buffer_file[i] ^= password[j];
            j++;
            if (j == password_length) {
                j = 0;
            }
        }
        fwrite(buffer_file,1,bytes_read,f_output);
    }
    fclose(f_input);
    fclose(f_output);
    return true;
}

bool check_file(const FILE* file) {
    if (file == NULL) {
        printf("Error while opening file or file doesn't exists!\n\n");
        return false;
    }
    return true;
}

void print_menu(){
    printf("\nMENU:");
    printf("\n1)Encrypt a file using XOR (obfuscation).");
    printf("\n2)Decrypt a file using XOR (obfuscation).");
    printf("\n3)Encrypt a file using AES-256.");
    printf("\n4)Decrypt a file using AES-256.");
    printf("\n0)Exit");
    printf("\nChoose: ");
}

void print_banner() {
    printf(
        "\n"
        "\n"
        " ██████╗██████╗ ██╗   ██╗██████╗ ████████╗██╗  ██╗ ██████╗ ██████╗ \n"
        "██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝╚██╗██╔╝██╔═══██╗██╔══██╗\n"
        "██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║    ╚███╔╝ ██║   ██║██████╔╝\n"
        "██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║    ██╔██╗ ██║   ██║██╔══██╗\n"
        "╚██████╗██║  ██║   ██║   ██║        ██║   ██╔╝ ██╗╚██████╔╝██║  ██║\n"
        " ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝\n"
        "\n"
        "                          by ShiroiShi\n"
        "\n"
        "Encrypt and decrypt your files using\n"
        "XOR obfuscation or authenticated AES-256-GCM."
        "\n"
    );
}

bool aes256_encryption(unsigned char* buffer_file,const char* file_name,const char* password) {
    FILE* f_input = NULL;
    FILE* f_output = NULL;
    char file_name_output[FILENAME_LEN];
    unsigned char key[KEY_LEN];
    unsigned char salt[SALT_LEN];
    unsigned char iv[IV_LEN];
    unsigned char tag[TAG_LEN];
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    strcpy(file_name_output,file_name);
    size_t bytes_read;
    int bytes_encrypted;
    unsigned char buffer_encrypted[BUFFER_LEN];
    if (ctx == NULL) {
        printf("NULL pointer,error!\n");
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    f_input = fopen(file_name,"rb");
    if (!check_file(f_input)) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    f_output = fopen(strcat(file_name_output,".enc"),"wb");
    if (!check_file(f_output)) {
        fclose(f_input);
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    randombytes_buf(salt,SALT_LEN);
    randombytes_buf(iv,IV_LEN);
    fwrite(salt,1,SALT_LEN,f_output);
    fwrite(iv,1,IV_LEN,f_output);
    if (crypto_pwhash(key,KEY_LEN,password,strlen(password),salt,crypto_pwhash_OPSLIMIT_MODERATE,crypto_pwhash_MEMLIMIT_MODERATE,crypto_pwhash_ALG_ARGON2ID13) != 0) {
        printf("Error while creating key!\n");
        clean_everything(f_input,f_output,file_name_output,ctx,key);
        return false;
    }
    if (EVP_EncryptInit_ex(ctx,EVP_aes_256_gcm(),NULL,key,iv) != 1) {
        printf("Error while encryption data!\n");
        clean_everything(f_input,f_output,file_name_output,ctx,key);
        return false;
    }
    while ((bytes_read = fread(buffer_file,1,BUFFER_LEN,f_input)) > 0) {
        if (EVP_EncryptUpdate(ctx,buffer_encrypted,&bytes_encrypted,buffer_file,(int)bytes_read) != SUCCESS) {
            printf("Error while encryption data!\n");
            clean_everything(f_input,f_output,file_name_output,ctx,key);
            return false;
        }
        fwrite(buffer_encrypted,1,bytes_encrypted,f_output);
    }
    if (EVP_EncryptFinal_ex(ctx,buffer_encrypted,&bytes_encrypted) != SUCCESS) {
        printf("Error while encryption data!\n");
        clean_everything(f_input,f_output,file_name_output,ctx,key);
        return false;
    }
    fwrite(buffer_encrypted,1,bytes_encrypted,f_output);
    if (EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_AEAD_GET_TAG,TAG_LEN,tag) != SUCCESS) {
        printf("Error while encryption data!\n");
        clean_everything(f_input,f_output,file_name_output,ctx,key);
        return false;
    }
    fwrite(tag,1,TAG_LEN,f_output);
    sodium_memzero(key,sizeof(key));
    fclose(f_input);
    fclose(f_output);
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool aes256_decryption(unsigned char* buffer_file,const char* file_name,const char* password) {
    FILE* f_input = NULL;
    FILE* f_output = NULL;
    char file_name_output[FILENAME_LEN];
    unsigned char key[KEY_LEN];
    unsigned char salt[SALT_LEN];
    unsigned char iv[IV_LEN];
    unsigned char tag[TAG_LEN];
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    strcpy(file_name_output,file_name);
    char* point = strrchr(file_name_output,'.');
    *point = '\0';
    size_t bytes_read;
    int bytes_decrypted;
    unsigned char buffer_decrypted[BUFFER_LEN];
    if (ctx == NULL) {
        printf("NULL pointer,error!\n");
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    f_input = fopen(file_name,"rb");
    if (!check_file(f_input)) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    f_output = fopen(file_name_output,"wb");
    if (!check_file(f_output)) {
        fclose(f_input);
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    fread(salt,1,SALT_LEN,f_input);
    fread(iv,1,IV_LEN,f_input);
    if (crypto_pwhash(key,KEY_LEN,password,strlen(password),salt,crypto_pwhash_OPSLIMIT_MODERATE,crypto_pwhash_MEMLIMIT_MODERATE,crypto_pwhash_ALG_ARGON2ID13) != 0) {
        printf("Error while creating key!\n");
        clean_everything(f_input,f_output,file_name_output,ctx,key);
        return false;
    }
    if (EVP_DecryptInit_ex(ctx,EVP_aes_256_gcm(),NULL,key,iv) != SUCCESS) {
        printf("Error while decryption data!\n");
        clean_everything(f_input,f_output,file_name_output,ctx,key);
        return false;
    }
    fseek(f_input,-TAG_LEN,SEEK_END);
    fread(tag,1,TAG_LEN,f_input);
    fseek(f_input,0,SEEK_END);
    long cipher_text_size = ftell(f_input) - SALT_LEN - IV_LEN - TAG_LEN;
    fseek(f_input,(SALT_LEN + IV_LEN),SEEK_SET);
    while (cipher_text_size > 0) {
        if (cipher_text_size > BUFFER_LEN) {
            bytes_read = fread(buffer_file,1,BUFFER_LEN,f_input);
        }
        else {
            bytes_read = fread(buffer_file,1,cipher_text_size,f_input);
        }
        if (EVP_DecryptUpdate(ctx,buffer_decrypted,&bytes_decrypted,buffer_file,(int)bytes_read) != SUCCESS) {
            printf("Error while decryption data!\n");
            clean_everything(f_input,f_output,file_name_output,ctx,key);
            return false;
        }
        fwrite(buffer_decrypted,1,bytes_decrypted,f_output);
        cipher_text_size -= (long)bytes_read;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_AEAD_SET_TAG,TAG_LEN,tag) != SUCCESS) {
        printf("Tag not valid,impossible to decrypt file!\n");
        clean_everything(f_input,f_output,file_name_output,ctx,key);
        return false;
    }
    if (EVP_DecryptFinal_ex(ctx,buffer_decrypted,&bytes_decrypted) != SUCCESS) {
        printf("Error while decryption data,incorrect password or corrupted file!\n");
        clean_everything(f_input,f_output,file_name_output,ctx,key);
        return false;
    }
    fwrite(buffer_decrypted,1,bytes_decrypted,f_output);
    sodium_memzero(key,sizeof(key));
    fclose(f_input);
    fclose(f_output);
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

void clean_everything(FILE* f_input,FILE* f_output,const char* file_name_output,EVP_CIPHER_CTX* ctx,unsigned char* key) {
    sodium_memzero(key,KEY_LEN);
    fclose(f_input);
    fclose(f_output);
    EVP_CIPHER_CTX_free(ctx);
    remove(file_name_output);
}
