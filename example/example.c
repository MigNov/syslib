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

	int app22 = syslibGetProcessIDByPort(22);
	if (app22 == 0)
		printf("No application found on port 22\n");
	else
		printf("Port 22 occupied by PID #%d [%s]\n", app22, syslibGetProcessNameByPID(app22));

	printf("syslibSysctlGet('net.core.rmem_max') returned %d\n", syslibSysctlGet("net.core.rmem_max"));

	char *drv = syslibInterfaceGetDriver(INTERFACE);
	char *drvVer = syslibInterfaceGetDriverVersion(INTERFACE);
	char *drvBus = syslibInterfaceGetDriverBusInfo(INTERFACE);
	char *drvFW = syslibInterfaceGetDriverFWVersion(INTERFACE);
	char *drvMAC = syslibInterfaceGetMACAddress(INTERFACE);
	printf("Interface %s driver: %s %s [bus %s; firmware: %s, mac: %s]\n", INTERFACE, drv, drvVer, drvBus, drvFW, drvMAC);
	free(drvMAC);
	free(drvFW);
	free(drvBus);
	free(drvVer);
	free(drv);

	if (syslibEnsureUUIDFile() != 0)
		printf("Warning: Cannot ensure that UUID file exists\n");
	else
		printf("UUID file exists\n");

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

	/* Test AES-128 encryption and decryption */
	char *enc = syslibAESEncrypt("test", 0);
	char *dec = syslibAESDecrypt(enc);
	printf("[AES-128] Encrypted 'test': %s\n", enc);
	printf("[AES-128] Decrypted '%s': %s\n", enc, dec);
	free(enc);
	free(dec);

	/* Test AES-256 encryption and decryption */
	char *enc2 = syslibAESEncrypt("test", 1);
	char *dec2 = syslibAESDecrypt(enc2);
	printf("[AES-256] Encrypted 'test': %s\n", enc2);
	printf("[AES-256] Decrypted '%s': %s\n", enc2, dec2);
	free(enc2);
	free(dec2);

	char *tmpIf = syslibQueryGetSingle("table", "val", shorthn, "interface = '"INTERFACE"'", NULL);
	printf("Value for %s is: %s\n", INTERFACE, tmpIf);
	free(tmpIf);

	syslibFree();

	free(shorthn);
	syslibFree();
	printf("syslibFree called\n");

	return 0;
}

