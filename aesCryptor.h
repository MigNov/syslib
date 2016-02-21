//#define DEBUG_AES

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <unistd.h>
#include <sys/types.h>

unsigned char *base64_encode(const unsigned char *in, int size);
unsigned char *base64_decode(const unsigned char *in, int *size);

char *systemGetUUID(void);
char *getMd5Sum(char *val);
unsigned char *aesEncryptData(unsigned char *input, char *uuid, int raw);
unsigned char *aesDecryptData(unsigned char *input, char *uuid, int raw);
unsigned char *aesProcessData(unsigned char *input, char *pass, int raw);

