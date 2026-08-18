#ifndef CRYPTXOR_CRYPTXOR_H
#define CRYPTXOR_CRYPTXOR_H

#define BUFFER_LEN 4096
#define FILENAME_LEN 1000
#define PASSWORD_LEN 100
#define KEY_LEN 32
#define SALT_LEN 16
#define IV_LEN 12
#define TAG_LEN 16

typedef enum{EXIT,XOR_ENCRYPT,XOR_DECRYPT,AES_ENCRYPT,AES_DECRYPT}Choice;
typedef enum{FAILURE,SUCCESS}Result;

bool xor_encryption(unsigned char* buffer_file,const char* file_name,const char* password);
bool xor_decryption(unsigned char* buffer_file,const char* file_name,const char* password);
bool check_file(const FILE* file);
void print_menu();
void print_banner();
bool aes256_encryption(unsigned char* buffer_file,const char* file_name,const char* password);
bool aes256_decryption(unsigned char* buffer_file,const char* file_name,const char* password);

#endif //CRYPTXOR_CRYPTXOR_H
