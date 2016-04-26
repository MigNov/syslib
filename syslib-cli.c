#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "include/syslib.h"

int numProcessed = 0;

void syslib_showVersion(void)
{
	int major, minor, micro;

	syslibGetVersion(&major, &minor, &micro);
	printf("%04d.%02d.%02d\n", major, minor, micro);
	numProcessed++;
}

void syslib_libIdent(void)
{
	char *ident = syslibGetIdentification();
	if (ident == NULL)
		printf("Error: Cannot get library identification");
	else {
		printf("Library syslib identification: %s\n", ident);
		free(ident);
	}

	numProcessed++;
}

void syslib_showUUID(void)
{
	char *uuid = syslibSystemUUID();
	if (uuid == NULL)
		printf("Error: Cannot get hardware identification");
	else {
		printf("%s\n", uuid);
		free(uuid);
	}

	numProcessed++;
}

void syslib_encrypt128(char *input)
{
	char *enc = syslibAESEncrypt(input, 0);
	if (enc == NULL)
		printf("Error: Cannot proceed with encryption");
	else {
		printf("%s\n", enc);
		free(enc);
	}

	numProcessed++;
}

void syslib_encrypt256(char *input)
{
	char *enc = syslibAESEncrypt(input, 1);
	if (enc == NULL)
		printf("Error: Cannot proceed with encryption");
	else {
		printf("%s\n", enc);
		free(enc);
	}

	numProcessed++;
}

void syslib_encrypt128p(char *input, char *p)
{
        char *enc = syslibAESEncryptPassword(input, p, 0);
        if (enc == NULL)
                printf("Error: Cannot proceed with encryption");
        else {
                printf("%s\n", enc);
                free(enc);
        }

        numProcessed++;
}

void syslib_encrypt256p(char *input, char *p)
{
        char *enc = syslibAESEncryptPassword(input, p, 1);
        if (enc == NULL)
                printf("Error: Cannot proceed with encryption");
        else {
                printf("%s\n", enc);
                free(enc);
        }

        numProcessed++;
}

void syslib_decrypt(char *input)
{
	char *dec = syslibAESDecrypt(input);
	if (dec == NULL)
		printf("Error: Decryption failed\n");
	else {
		printf("%s\n", dec);
		free(dec);
	}

	numProcessed++;
}

void syslib_decryptp(char *input, char *p)
{
	char *dec = syslibAESDecryptPassword(input, p);
	if (dec == NULL)
		printf("Error: Decryption failed\n");
	else {
		printf("%s\n", dec);
		free(dec);
	}

	numProcessed++;
}

void syslib_help(void)
{
	char *ident = syslibGetIdentification();
	if (ident != NULL)
		printf("%s\n\n", ident);
	free(ident);

	printf("Error: Sub-command is missing\n\n");
	printf("Valid sub-commands are:\n\n");
	printf("\t--version|-v\t\t- show syslib version\n");
	printf("\t--ident|-i\t\t- show library identification\n");
	printf("\t--hwid|-u\t\t- show hardware identification\n");
	printf("\t--encrypt-128|-1\t- do AES-128 encryption\n");
	printf("\t--encrypt-256|-2\t- do AES-256 encryption\n");
	printf("\t--encrypt-128p|-3\t- do AES-128 encryption with custom password\n");
	printf("\t--encrypt-256p|-4\t- do AES-256 encryption with custom password\n");
	printf("\t--decrypt|-d\t\t- do decryption\n");
	printf("\t--decryptp|-5\t\t- do decryption with custom password\n");
	printf("\n");

	numProcessed++;
}

int main(int argc, char *argv[])
{
	int rv = 0;
	char *rvc = NULL;
	int major, minor, micro;

	int i;
	for (i = 0; i < argc; i++) {
		if ((strcmp(argv[i], "--version") == 0) || (strcmp(argv[i], "-v") == 0))
			syslib_showVersion();
		if ((strcmp(argv[i], "--ident") == 0) || (strcmp(argv[i], "-i") == 0))
			syslib_libIdent();
		if ((strcmp(argv[i], "--hwid") == 0) || (strcmp(argv[i], "-u") == 0))
			syslib_showUUID();
		if ((strcmp(argv[i], "--encrypt-128") == 0) || (strcmp(argv[i], "-1") == 0)) {
			if (i < argc - 1)
				syslib_encrypt128(argv[i + 1]);
		}
		if ((strcmp(argv[i], "--encrypt-256") == 0) || (strcmp(argv[i], "-2") == 0)) {
			if (i < argc - 1)
				syslib_encrypt256(argv[i + 1]);
		}
		if ((strcmp(argv[i], "--encrypt-128p") == 0) || (strcmp(argv[i], "-3") == 0)) {
                        if (i < argc - 2)
                                syslib_encrypt128p(argv[i + 1], argv[i + 2]);
                }
                if ((strcmp(argv[i], "--encrypt-256p") == 0) || (strcmp(argv[i], "-4") == 0)) {
                        if (i < argc - 2)
                                syslib_encrypt256p(argv[i + 1], argv[i + 2]);
                }
		if ((strcmp(argv[i], "--decrypt") == 0) || (strcmp(argv[i], "-d") == 0)) {
			if (i < argc - 1)
				syslib_decrypt(argv[i + 1]);
		}
		if ((strcmp(argv[i], "--decryptp") == 0) || (strcmp(argv[i], "-5") == 0)) {
			if (i < argc - 2)
				syslib_decryptp(argv[i + 1], argv[i + 2]);
		}
		if ((strcmp(argv[i], "--help") == 0) || (strcmp(argv[i], "-h") == 0))
			syslib_help();
	}

	if (numProcessed == 0)
		syslib_help();

	return 0;
}

