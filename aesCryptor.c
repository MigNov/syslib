#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include <pthread.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "aesCryptor.h"

// Use AES-128
//#define	METHOD		EVP_aes_128_cbc
//#define 	LEN_IV		16
//#define 	LEN_IVB64	24

// Use AES-256
#define		METHOD		EVP_aes_256_cbc
#define		LEN_IV		32
#define		LEN_IVB64	44

/* Prototype */
long _gettid(void);

int aesEncrypt(unsigned char *aesKey, unsigned char *aesIV, const unsigned char *msg, size_t msgLen, unsigned char **encMsg)
{
	int i;
	size_t blockLen  = 0;
	size_t encMsgLen = 0;
	EVP_CIPHER_CTX *aesCtx = NULL;

#ifdef DEBUG_AES
	printf("[debug/crypto] aesEncrypt key: ");
	for (i = 0; i < strlen(aesKey); i++)
		printf("%02X ", aesKey[i]);
	printf("\n");

	printf("[debug/crypto] aesEncrypt vector: ");
	for (i = 0; i < LEN_IV; i++)
		printf("%02X ", aesIV[i]);
	printf("\n");
#endif

	aesCtx = (EVP_CIPHER_CTX *)malloc(sizeof(EVP_CIPHER_CTX));
	if (aesCtx == NULL)
		return -1;

	EVP_CIPHER_CTX_init(aesCtx);

 	*encMsg = (unsigned char*)malloc(msgLen + LEN_IV);
	if(encMsg == NULL)
		return -1;
 
	if(!EVP_EncryptInit_ex(aesCtx, METHOD(), NULL, aesKey, aesIV))
		return -2;
 
	if (!EVP_EncryptUpdate(aesCtx, *encMsg, (int*)&blockLen, (unsigned char*)msg, msgLen))
		return -3;

	encMsgLen += blockLen;
 
	if (!EVP_EncryptFinal_ex(aesCtx, *encMsg + encMsgLen, (int*)&blockLen)) {
		return -4;
	}
 
	EVP_CIPHER_CTX_cleanup(aesCtx);
	free(aesCtx);
 
	return encMsgLen + blockLen;
}

int aesDecrypt(unsigned char *aesKey, unsigned char *aesIV, unsigned char *encMsg, size_t encMsgLen, unsigned char **decMsg)
{
	int i, ret = 0;
	size_t decLen = 0;
	size_t blockLen = 0;
	EVP_CIPHER_CTX *aesCtx = NULL;

	if ((aesIV == NULL) || (encMsg == NULL))
		return -EINVAL;

#ifdef DEBUG_AES
	printf("[debug/crypto] aesDecrypt key: ");
	for (i = 0; i < strlen(aesKey); i++)
		printf("%02X ", aesKey[i]);
	printf("\n");

	printf("[debug/crypto] aesDecrypt vector: ");
	for (i = 0; i < LEN_IV; i++)
		printf("%02X ", aesIV[i]);
	printf("\n");
#endif

	aesCtx = (EVP_CIPHER_CTX *)malloc(sizeof(EVP_CIPHER_CTX));
	if (aesCtx == NULL) {
		ret = -1;
		goto cleanup;
	}

	EVP_CIPHER_CTX_init(aesCtx);

	*decMsg = (unsigned char*)malloc(encMsgLen);
	memset(*decMsg, 0, encMsgLen);
	if (*decMsg == NULL) {
		ret = -2;
		goto cleanup;
	}

	if (!EVP_DecryptInit_ex(aesCtx, METHOD(), NULL, aesKey, aesIV)) {
		ret = -3;
		goto cleanup;
	}

	if (!EVP_DecryptUpdate(aesCtx, (unsigned char*)*decMsg, (int*)&blockLen, encMsg, (int)encMsgLen)) {
		ret = -4;
		goto cleanup;
	}

	decLen += blockLen;

	if (!EVP_DecryptFinal_ex(aesCtx, (unsigned char*)*decMsg + decLen, (int*)&blockLen)) {
		ret = -5;
		goto cleanup;
	}

	decLen += blockLen;

	ret = (int)decLen;
cleanup:
//	if (*decMsg != NULL)
//		free(decMsg);

	if (aesCtx != NULL) {
		EVP_CIPHER_CTX_cleanup(aesCtx);
		free(aesCtx);
	}

	return ret;
}

char *systemGetUUID_dmidecode(void)
{
	char uuid[128] = { 0 };
	char cmd[1024] = { 0 };
	FILE *fp = NULL;

	if (getuid() != 0)
		return NULL;

	snprintf(cmd, sizeof(cmd), "dmidecode | grep UUID | awk '{split($0, a, \": \"); print a[2]}'");

	fp = popen(cmd, "r");
	if (fp == NULL)
		return NULL;

	fgets(uuid, sizeof(uuid), fp);
	fclose(fp);

	if (strlen(uuid) == 0) {
		snprintf(cmd, sizeof(cmd), "dmidecode | md5sum | awk '{split($0, a, \" \"); print a[1]}'");

		fp = popen(cmd, "r");
		if (fp != NULL) {
			fgets(uuid, sizeof(uuid), fp);
			fclose(fp);
		}
	}

	if (strlen(uuid) > 0)
		uuid[strlen(uuid) - 1] = 0;

	return strdup(uuid);
}

char *systemGetUUID_binary(void)
{
	char uuid[128] = { 0 };

	FILE *fp = popen("getsysuuid 2> /dev/null", "r");
	if (fp == NULL)
		return NULL;
	fgets(uuid, sizeof(uuid), fp);
	fclose(fp);

	if (strlen(uuid) == 0)
		return NULL;

	return strdup(uuid);
}

char *systemGetUUID_file(void)
{
	char uuid[128] = { 0 };
	FILE *fp = fopen("/etc/machine-uuid", "r");
	if (fp == NULL)
		return NULL;

	fgets(uuid, sizeof(uuid), fp);
	fclose(fp);

	return strdup(uuid);
}

char *systemGetUUID(void)
{
	char *uuid = NULL;

	// No root required
	if ((uuid = systemGetUUID_binary()) != NULL)
		return uuid;
	if ((uuid = systemGetUUID_file()) != NULL)
		return uuid;
	// Requires root access
	if ((uuid = systemGetUUID_dmidecode()) != NULL)
		return uuid;

	return NULL;
}


unsigned char *UUIDToRaw(char *uuid, int len)
{
	int rlen, val, doFree = 0;
	int skipped = 0, i = 0;
	unsigned char tmp[3] = { 0 };
	unsigned char *ret = NULL;

	if (uuid == NULL) {
		uuid = systemGetUUID();
		doFree = 1;
	}

	if (uuid == NULL)
		return NULL;

	ret = (unsigned char *)malloc( len * sizeof(unsigned char) );
	memset(ret, 0, len * sizeof(unsigned char) );
	while (i < strlen(uuid)) {
		if (uuid[i] == '-') {
			i++;
			skipped++;
		}
		tmp[0] = uuid[i];
		tmp[1] = uuid[i+1];

		i += 2;
		sscanf(tmp, "%02X", &val);

		rlen = (i - skipped) / 2;
		if (rlen > len)
			break;

		ret[rlen - 1] = val;
	}

	int j;
	for (i = 1; i < len / (strlen(uuid) / 2); i++)
		for (j = 0; j < 16; j++) {
			ret[((i - 0) * 16) + j] = ret[j];
		}

	if (doFree == 1)
		free(uuid);

	return ret;
}

unsigned char *base64_encode(const unsigned char *in, int size)
{
	FILE *fp;
	unsigned char s[1024] = { 0 };

	unlink("/tmp/test.tmpe");
	unlink("/tmp/test.tmpe2");

	fp = fopen("/tmp/test.tmpe", "w");
	fwrite(in, size, 1, fp);
	fclose(fp);

	system("base64 /tmp/test.tmpe | tr -d '\n' > /tmp/test.tmpe2");

	int fd = open("/tmp/test.tmpe2", O_RDONLY);
	read(fd, s, sizeof(s));
	close(fd);

	if (s[strlen(s) - 1] == '\n')
		s[strlen(s) - 1] = 0;

	unlink("/tmp/test.tmpe");
	unlink("/tmp/test.tmpe2");

	return strdup(s);
}

unsigned char *base64_decode(const unsigned char *in, int *size)
{
	int rv;
	FILE *fp;
	unsigned char *s;
	char tmp[4096]  = { 0 };
	char tmp1[1024] = { 0 };
	char tmp2[1024] = { 0 };

	snprintf(tmp1, sizeof(tmp1), "/tmp/test.tmpd.%d", _gettid());
	snprintf(tmp2, sizeof(tmp2), "/tmp/test.tmpd2.%d", _gettid());

	unlink(tmp1);
	unlink(tmp2);

	fp = fopen(tmp1, "w");
	fwrite(in, *size, 1, fp);
	fclose(fp);

	snprintf(tmp, sizeof(tmp), "base64 -d %s > %s 2> /dev/null",
		tmp1, tmp2);

	system(tmp);

	s = (unsigned char *)malloc( 1024 * sizeof(unsigned char));
	fp = fopen(tmp2, "r");
	if (fp == NULL)
		return NULL;

	fread(s, 1024, 1, fp);
	fclose(fp);

	int fd = open(tmp2, O_RDONLY);
	rv = lseek(fd, 0, SEEK_END);
	close(fd);

	unlink(tmp1);
	// Make sure we won't run into issues again on other systems
	chmod(tmp2, 0666);

	if (size != NULL)
		*size = rv;
	return s;
}

char *getMd5Sum(char *val)
{
	FILE *fp = NULL;
	char md5[33] = { 0 };
	char cmd[1024] = { 0 };

	snprintf(cmd, sizeof(cmd), "echo -n %s | md5sum", val);

	fp = popen(cmd, "r");
	fgets(md5, sizeof(md5), fp);
	fclose(fp);

	return strdup(md5);
}

unsigned char *aesEncryptDataSafe(unsigned char *input, int len, char *pass, int raw)
{
	int i, fd, aesLen, tLen;
	char *ret = NULL;
	char *ivStr = NULL;
	char *retStr = NULL;
	unsigned char *iv = NULL;
	unsigned char *key = NULL;
	unsigned char *retMsg = NULL;

        if (pass == NULL)
                key = UUIDToRaw(NULL, LEN_IV);
        if ((pass != NULL) && (raw == 1))
                key = UUIDToRaw(pass, LEN_IV);
        if ((pass != NULL) && (raw == 0))
                key = UUIDToRaw(getMd5Sum(pass), LEN_IV);

	if (key == NULL)
		return NULL;

//	free(key); return NULL;

	iv = (unsigned char *)malloc( LEN_IV * sizeof(unsigned char) );
	memset(iv, 0, sizeof(iv));

	/* Get LEN_IV random bytes for IV */
	fd = open("/dev/urandom", O_RDONLY);
	read(fd, iv, LEN_IV);
	close(fd);

#ifdef DEBUG_AES
	printf("[debug/crypto] Encryption key value: ");
	for (i = 0; i < strlen(key); i++)
		printf("%02X ", key[i]);
	printf("\n");
	printf("[debug/crypto] Generated encryption vector: ");
	for (i = 0; i < LEN_IV; i++)
		printf("%02X", iv[i]);
	printf("\n");
#endif

	aesLen = aesEncrypt(key, iv, input, len, &retMsg);

#ifdef DEBUG_AES
	printf("[debug/crypto] Encrypted key length: %d\n", aesLen);
#endif

	ivStr = base64_encode(iv, LEN_IV);
	retStr = base64_encode(retMsg, aesLen);

	tLen = strlen(ivStr) + strlen(retStr) + 1;
	ret = malloc( tLen * sizeof(unsigned char) );

	snprintf(ret, tLen, "%s%s", ivStr, retStr);

#ifdef DEBUG_AES
	printf("[debug/crypto] Encrypted message length: %d\n", strlen(ret));
#endif

	free(iv);
	free(key);
	free(ivStr);
	free(retMsg);
	free(retStr);

	return ret;
}

unsigned char *aesEncryptData(unsigned char *input, char *pass, int raw)
{
	return aesEncryptDataSafe(input, strlen(input), pass, raw);
}

unsigned char *aesDecryptDataSafe(unsigned char *input, int *size, char *pass, int raw)
{
	int i, msgLen, aesLen, ivB64s;
	unsigned char *iv = NULL;
	unsigned char *key = NULL;
	unsigned char *msg = NULL;
	unsigned char *ivB64 = NULL;
	unsigned char *retMsg = NULL;

	if (pass == NULL)
		key = UUIDToRaw(NULL, LEN_IV);
	else
	if ((pass != NULL) && (raw == 1))
		key = UUIDToRaw(pass, LEN_IV);
	if ((pass != NULL) && (raw == 0))
		key = UUIDToRaw(getMd5Sum(pass), LEN_IV);

	/* Get first base64 encoded LEN_IV bytes and decode them - IV */
	ivB64 = (unsigned char *)malloc( LEN_IVB64 * sizeof(unsigned char) );
	if (ivB64 == NULL) {
		errno = -ENOMEM;
		return NULL;
	}
	memcpy(ivB64, input, LEN_IVB64);
	ivB64s = LEN_IVB64;
	iv = base64_decode(ivB64, &ivB64s);
	msgLen = strlen(input) - LEN_IVB64;
	msg = base64_decode(input + LEN_IVB64, &msgLen);

#ifdef DEBUG_AES
	printf("[debug/crypto] Encrypted input: '%s'\n", input);
	printf("[debug/crypto] Encrypted vector in base64 form: '%s'\n", ivB64);
	printf("[debug/crypto] Encrypted message: '%s'\n", input + LEN_IVB64);

	printf("[debug/crypto] Decryption key value: ");
	for (i = 0; i < LEN_IV; i++)
		printf("%02X ", key[i]);
	printf("\n");
	printf("[debug/crypto] Decryption vector: ");
	for (i = 0; i < LEN_IV; i++)
		printf("%02X", iv[i]);
	printf("\n");
#endif

	aesLen = aesDecrypt(key, iv, msg, msgLen, &retMsg);
	if (aesLen > 0)
		retMsg[aesLen] = 0;
	else
		retMsg = NULL;

	if (size != NULL)
		*size = aesLen;

#ifdef DEBUG_AES
	printf("[debug/crypto] Decrypted message length: %d\n", aesLen);
#endif

	free(ivB64);
	free(msg);
	free(key);
	free(iv);

	return retMsg;
}

unsigned char *aesDecryptData(unsigned char *input, char *pass, int raw)
{
	return aesDecryptDataSafe(input, NULL, pass, raw);
}

unsigned char *aesProcessData(unsigned char *input, char *pass, int raw)
{
	if (input == NULL)
		return NULL;

	int decrypt = (strncmp(input, "$9$", 3) == 0) ? 1 : 0;
#ifdef DEBUG_AES
	printf("[debug/crypto] Detected mode: %scryption\n", decrypt ? "De" : "En");
#endif
	if (decrypt)
                return aesDecryptData(input + 3, pass, raw);
        else {
		unsigned char *tmp = (unsigned char *)malloc( (strlen(input) + 3) *
					sizeof(unsigned char));
		unsigned char *enc = aesEncryptData(input, pass, raw);

		strcpy(tmp, "$9$");
		strcat(tmp, enc);
		free(enc);
		
                return tmp;
	}
}

