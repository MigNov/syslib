#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/syslib.h"

#define	INTERFACE	"enp0s25"

int main(void)
{
	int rv = 0;
	char *rvc = NULL;
	int major, minor, micro;

	syslibGetVersion(&major, &minor, &micro);
	printf("syslibGetVersion returned { major: %d, minor: %d, micro: %d }\n", major, minor, micro);

	int x, ix;
	char **parts = syslibGetPartitionList(&x);
	for (ix = 0; ix < x; ix ++) {
		printf("Partition #%d: %s\n", ix, parts[ix]);
		free(parts[ix]);
	}
	free(parts);

	char *drv = syslibInterfaceGetDriver(INTERFACE);
	if (drv != NULL) {
		int rx, rx_mini, rx_jumbo;
		syslibInterfaceGetRxRingSize(INTERFACE, &rx, &rx_mini, &rx_jumbo);
		printf("Interface %s: RX ring size is %d\n", INTERFACE, rx);
		if (syslibInterfaceGetFlag(INTERFACE, IF_TSO) == 1) {
			printf("Interface %s: TCP-Segment-offloading enabled. Disabling ... ", INTERFACE);
			if (syslibInterfaceSetFlag(INTERFACE, IF_TSO, 0) == 0)
				printf("done\n");
			else
				printf("error!\n");
		}
		else
			printf("Interface %s: TCP-Segment-offloading disabled - OK\n", INTERFACE);

		if (syslibInterfaceGetPromisc(INTERFACE) == 0) {
			printf("Interface %s: Not in promisc. mode. Enabling ... ", INTERFACE);
			if (syslibInterfaceSetPromisc(INTERFACE, 1) == 0)
				printf("done\n");
			else
				printf("error!\n");
		}
		else
			printf("Interface %s is already promisc. mode\n", INTERFACE);
	}

	int app22 = syslibGetProcessIDByPort(22);
	if (app22 == 0)
		printf("No application found on port 22\n");
	else
		printf("Port 22 occupied by PID #%d [%s]\n", app22, syslibGetProcessNameByPID(app22));

	printf("syslibSysctlGet('net.core.rmem_max') returned %d\n", syslibSysctlGet("net.core.rmem_max"));

	char *drvVer = syslibInterfaceGetDriverVersion(INTERFACE);
	char *drvBus = syslibInterfaceGetDriverBusInfo(INTERFACE);
	char *drvFW = syslibInterfaceGetDriverFWVersion(INTERFACE);
	char *drvMAC = syslibInterfaceGetMACAddress(INTERFACE);
	if (drv != NULL)
		printf("Interface %s driver: %s %s [bus %s; firmware: %s, mac: %s]\n", INTERFACE, drv, drvVer, drvBus, drvFW, drvMAC);
	else
		printf("Interface %s information cannot be retrieved\n", INTERFACE);
	free(drvMAC);
	free(drvFW);
	free(drvBus);
	free(drvVer);
	free(drv);

	if (syslibEnsureUUIDFile() != 0)
		printf("Warning: Cannot ensure that UUID file exists\n");
	else
		printf("Information: UUID file exists\n");

	char *shorthn = syslibGetShortHostName();
	printf("Short hostname is: %s\n", shorthn);

	char *cs = syslibGetConnectionString("DBConnection");
	printf("DBConnection => %s\n", cs);
	free(cs);

	rv = syslibInit("DBConnnection", NULL);
	//syslibSetLogging("EX", LOG_LEVEL_ALL);
	if (rv != 0)
		printf("syslibInit returned %d\n", rv);

	char **vars = malloc( 5 * sizeof(char *) );
//	char **vals = malloc( 4 * sizeof(char *) );
	vars[0] = strdup("var1");
	vars[1] = strdup("var4");
	vars[2] = strdup("var3");
	vars[3] = strdup("var2");
	vars[4] = strdup("fld");
/*
	vals[0] = strdup("val1");
	vals[1] = strdup("val2");
	vals[2] = strdup("val3");
	vals[3] = strdup("val4");
*/
	//syslibQueryInsert("testtab", 4, vars, vals);

	int i, num;
	char **ret = syslibQueryGetArray("testtab2", "fld", &num, "test", NULL);


	if (ret != NULL) {
		for (i = 0; i < num; i++) {
			if (ret[i] != NULL) {
				printf("Select query returned array element #%d for 'fld': '%s'\n", i, ret[i]);
				free(ret[i]);
			}
		}
	}

	tQueryResult res = syslibQuerySelect("testtab2", 5, vars, "WHERE var4 = 21");
	//tQueryResult res = syslibQuerySelect("testtab2", 5, vars, NULL);
	syslibQueryResultDump(res);
	syslibQueryResultFree(res);

	for (i = 0; i < 5; i++)
		free(vars[i]);
	free(vars);

	char *uuid = syslibSystemUUID();
	printf("UUID: %s\n", uuid);
	free(uuid);

	printf("Running encryption using AES-128 ...\n");

	/* Test AES-128 encryption and decryption */
	char *enc = syslibAESEncrypt("test", 0);

	printf("Running decryption using AES-128 ...\n");

	char *dec = syslibAESDecrypt(enc);
	printf("[AES-128] Encrypted 'test': %s\n", enc);
	printf("[AES-128] Decrypted '%s': %s\n", enc, dec);
	free(enc);
	free(dec);

	printf("Running encryption using AES-256 ...\n");

	/* Test AES-256 encryption and decryption */
	char *enc2 = syslibAESEncrypt("test", 1);

	printf("Running decryption using AES-256 ...\n");

	char *dec2 = syslibAESDecrypt(enc2);
	printf("[AES-256] Encrypted 'test': %s\n", enc2);
	printf("[AES-256] Decrypted '%s': %s\n", enc2, dec2);
	free(enc2);
	free(dec2);

	char *ident = syslibGetIdentification();
	printf("Library syslib identification: %s\n", ident);
	free(ident);

	if (syslibIsPrivileged()) {
		unlink("/tmp/test.img");
		if (syslibCryptCreateWithExt4("/tmp/test.img", 8, "test"))
			printf("Warning: Cannot create /tmp/test.img\n");
		else {
			int rc;
			tDirListing dl;
			tCryptSpace csp;

			printf("File /tmp/test.img of 8 MiB created\n");

			rc = syslibCryptMkdir("/tmp/test.img", "test", "testdir", "0755");
			if (rc != 0)
				printf("syslibCryptMkdir error #%d\n", rc);

			rc = syslibCryptFileWrite("/tmp/test.img", "test", "testdir/test.file", "Test data file...");
			if (rc != 0)
				printf("syslibCryptFileWrite error #%d\n", rc);

			rc = syslibCryptFileWrite("/tmp/test.img", "test", "testdir/test2.file", "Test data file 2...");
			if (rc != 0)
				printf("syslibCryptFileWrite error #%d\n", rc);

			printf("Creating /tmp/local-file (4 MiB) for upload as testdir/copied.file\n");
			rc = syslibFileCreateEmpty("/tmp/local-file", 4);
			if (rc != 0)
				printf("syslibFileCreateEmpty error #%d\n", rc);

			printf("Copying /tmp/local-file as testdir/copied.file to encrypted volume\n");
			rc = syslibCryptFileCopy("/tmp/test.img", "test", "/tmp/local-file", "testdir/copied.file");
			if (rc != 0)
				printf("syslibCryptFileCopy error #%d\n", rc);

			csp = syslibCryptGetSpace("/tmp/test.img", "test");
			printf("syslibCryptGetSpace = { total: %ld, used: %ld, avail: %ld, percent: %d%% }\n",
				csp.total, csp.used, csp.avail, csp.percent);

			printf("Deleting testdir/copied.file\n");
			rc = syslibCryptFileDelete("/tmp/test.img", "test", "testdir/copied.file");
			if (rc != 0)
				printf("syslibCryptFileCopy error #%d\n", rc);

			csp = syslibCryptGetSpace("/tmp/test.img", "test");
			printf("syslibCryptGetSpace = { total: %ld, used: %ld, avail: %ld, percent: %d%% }\n",
				csp.total, csp.used, csp.avail, csp.percent);

			dl = syslibCryptList("/tmp/test.img", "test", "testdir");
			if (dl.files > 0) {
				int i;

				printf("File count: %d\nFiles:\n", dl.files);
				for (i = 0; i < dl.files; i++)
					printf("  %s\n", dl.filenames[i]);
			}
			syslibDirListingFree(dl);

			char *data = syslibCryptFileRead("/tmp/test.img", "test", "testdir/test.file");
			printf("syslibCryptFileRead read data: '%s'\n", data);
			free(data);
		}
	}
	else
		printf("[SKIP] Not running as privileged user\n");

	char *rev = syslibGetRevision();
	printf("Library syslib revision: %s\n", rev);
	free(rev);

	char *tmpIf = syslibQueryGetSingle("table", "val", shorthn, "interface = '"INTERFACE"'", NULL);
	if (tmpIf != NULL)
		printf("Value for %s is: %s\n", INTERFACE, tmpIf);
	else
		printf("Value for %s is NULL\n", INTERFACE);
	free(tmpIf);

	syslibFree();

	free(shorthn);
	syslibFree();
	printf("syslibFree called\n");

	return 0;
}

