#ifndef SYSLIB_H
#define SYSLIB_H

#include <linux/ethtool.h>

#define	IF_RXCS		0x01
#define	IF_TXCS		0x02
#define	IF_SG		0x04
#define	IF_TSO		0x08
#define	IF_UFO		0x10
#define	IF_GSO		0x20
#define	IF_GRO		0x40
#define	IF_LRO		0x80
#define	IF_RXVLAN	0x100
#define	IF_TXVLAN	0x200
#define	IF_RXHASH	0x400

#define	DB_TYPE_NONE	0x00
#define	DB_TYPE_MYSQL	0x01
#define	DB_TYPE_PGSQL	0x02
#define	DB_TYPE_SQLITE	0x04

#define	ARRAY_CARDINALITY(x)	(sizeof(x) / sizeof(x[0]))

/* Error codes */
#define ERROR_BASE		2000
#define	ERR_CHECK_FAILED_CORES	ERROR_BASE + 1
#define	ERR_CHECK_FAILED_MEMORY	ERROR_BASE + 2
#define ERR_CHECK_FAILED_DISKS	ERROR_BASE + 3
#define ERR_NO_ARGS		ERROR_BASE + 4
#define	ERR_NO_IFCFG		ERROR_BASE + 5

#define	LOG_DEBUG		0x00
#define	LOG_ERROR		0x01
#define	LOG_SQL			0x02

#define	LOG_LEVEL_INFO		0x01
#define	LOG_LEVEL_ERROR		0x02
#define	LOG_LEVEL_WARNING	0x04
#define LOG_LEVEL_VERBOSE	0x08
#define LOG_LEVEL_DEBUG		0x10

#define LOG_LEVEL_ALL           LOG_LEVEL_INFO | LOG_LEVEL_ERROR | LOG_LEVEL_WARNING | LOG_LEVEL_VERBOSE | LOG_LEVEL_DEBUG

typedef struct tDirListing {
	int files;
	char **filenames;
} tDirListing;

typedef struct tCryptSpace {
	char *dev;
	unsigned long total;
	unsigned long used;
	unsigned long avail;
	unsigned short percent;
} tCryptSpace;

typedef struct tTokenizer {
	char **tokens;
	int numTokens;
} tTokenizer;

typedef struct tInstance {
	long id;
	char *dbconn;
	void *dbconnptr;
	int initdone;
	char *debugFile;
	int debugFlags;
} tInstance;

typedef struct tQueryField {
	char *name;
	char *val;
	int nParsedVals;
	char **parsedVals;
} tQueryField;

typedef struct tQueryRow {
	int nFields;
	tQueryField *fields;
} tQueryRow;

typedef struct tQueryResult {
	int nRows;
	tQueryRow *rows;
} tQueryResult;

typedef void (*tSQLiteMessageFunc) (char *);
typedef void (*tPQMessageProcesorFunc) (void *arg, void *message);

// utils.c
void systemReboot(void);
int systemServiceRestart(char *service);
char *strerrorShell(int errnum);
tTokenizer tokenize(char *string, char *by);
void tokensFree(tTokenizer t);
char *decbin(int n);
int getAddressMatch(char *ip, char *mask);
int isAllowedIp(char *ip, int userSpecific);
void printfTab(const char* format, ...);
void printfTimes(const char *format, int times);
time_t getMTime(char *filename);
char *getRemoteIP(void);
int checkRequirements(int reqCores, int reqMem, int reqDiskSize);
void logAction(char *action, int rv);
int _confLoad(char *filename);
void _confFree(void);
char *confGet(char *key);
void libLogToFile(int logType, const char *fmt,...);

// commands.c
int commandDisks(char *str);
int commandNetwork(char *str);

// database.c
char *pqSelect(char *query, char *field);
tQueryResult pqSelectAdvanced(char *query, int numFields, char **fields);
int pqExecute(char *query);

/* Public functions */
extern int    syslibInit(char *key, char *appname);
extern int    syslibConfSensorOnly(void);
extern int    syslibSetLogging(char *debugFile, int flags);
extern void   syslibDebugDump(void);
extern char * syslibSystemUUID(void);
extern int    syslibEnsureUUIDFile(void);
extern char * syslibGetShortHostName(void);
extern char * syslibGetRevision(void);
extern unsigned int syslibConvertTimestampToUnix(char *ts);
extern char * syslibQueryGetSingle(char *table, char *field, char *sensor, char *conditionAppend, char *def);
extern char **syslibQueryGetArray(char *table, char *field, int *out, char *sensor, char *conditionAppend);
extern int    syslibGetVersion(int *major, int *minor, int *micro);
extern char * syslibAESEncrypt(char *str, int useAES256);
extern char * syslibAESDecrypt(char *str);
extern int    syslibEnvSet(char *name, char *val);
extern char * syslibEnvGet(char *name);
extern char * syslibGetConnectionString(char *key);
extern int    syslibQueryInsert(char *table, int numVals, char **vars, char **vals);
tQueryResult  syslibQuerySelect(char *table, int numVars, char **vars, char *condition);
extern int    syslibQueryResultDump(tQueryResult res);
extern int    syslibQueryResultFree(tQueryResult res);
extern int    syslibEventInsert(char *hn, int typ, char *ipAddr, char *macAddr, int port, char *desc);
extern int    syslibEventPropagate(char *hn, char *timestamp);
extern int    syslibGetPartitionInfo(char *path, unsigned long *size, unsigned long *free, unsigned long *used);
extern char **syslibGetPartitionList(int *num);
extern int    syslibInterfaceSetRxRingSize(char *dev, int val);
extern int    syslibInterfaceGetRingSize(char *dev, struct ethtool_ringparam *oring);
extern int    syslibInterfaceGetRxRingSize(char *dev, int *rx, int *rx_mini, int *rx_jumbo);
extern int    syslibInterfaceGetFlag(char *dev, int flag);
extern int    syslibInterfaceSetFlag(char *dev, int flag, int val);
extern int    syslibInterfaceGetMTU(char *dev);
extern int    syslibInterfaceSetMTU(char *dev, int mtu);
extern int    syslibInterfaceGetPromisc(char *dev);
extern int    syslibInterfaceSetPromisc(char *dev, int val);
extern char * syslibInterfaceGetDriver(char *dev);
extern char * syslibInterfaceGetDriverVersion(char *dev);
extern char * syslibInterfaceGetDriverBusInfo(char *dev);
extern char * syslibInterfaceGetDriverFWVersion(char *dev);
extern char * syslibInterfaceGetMACAddress(char *dev);
extern long   syslibSysctlGet(char *var);
extern int    syslibSysctlSet(char *var, long value);
extern int    syslibGetProcessIDByPort(int port);
extern char * syslibGetProcessNameByPID(int pid);
extern int    syslibSetLocalizationPath(char *path);
extern char * syslibGetLocalizedString(char *lang, char *ident);
extern void   syslibPrintLocalizedString(char *lang, char *ident);
extern void   syslibSetCursor(int enable);
extern char * syslibGetDNSSetup(void);
extern int    syslibSetDNSSetup(char *dns);
extern int    syslibIsValidIPv4(char *ip);
extern int    syslibRunCountdown(int allowBreak, int sec, char *msgStart, char *msgProgress, char *msgDone);
extern void   syslibScheduleCommand(char *cmd, int min);
extern void   syslibSystemReboot(void);
extern void   syslibSystemShutdown(void);
extern int    syslibSystemChangePassword(char *user, char *password, char *chrootdir);
extern int    syslibIsOnSSH(void);
extern char * syslibGetBestCrypto(int *oSpeedEnc, int *oSpeedDec, int *oTimeTotal, char *message, char *finishMsg);
extern int    syslibSSHGeneralStateSet(int state);
extern int    syslibSSHGeneralStateGet(void);
extern int    syslibSSHUserStateCreate(void);
extern int    syslibSSHUserStateSet(char *user, int state);
extern int    syslibSSHUserStateGet(char *user);
extern int    syslibSSHUserStateIPCreate(void);
extern int    syslibSSHUserStateIPSet(char *user, char *ip, int state);
extern int    syslibSSHUserStateIPGet(char *user, char *ip);
extern int    syslibSSHUserStateMsgCreate(void);
extern int    syslibSSHUserStateCreateAll(void);
extern int    syslibKeyPressed(void);
extern int    syslibConvertSizeK(float val, char *unit);
extern unsigned int syslibIPToInt(char *ip);
extern char * syslibIntToIP(unsigned int ip);
extern int    syslibIsIPInSubnet(char *ip, char *cidr);
extern int    syslibSSHUserStateFileSet(char *fn);
extern int    syslibUserLoginMessageHandlerSet(void);
extern int    syslibUserLoginMessageHandlerUnset(void);

extern int    syslibCommandRun(char *cmd);
extern int    syslibFileCreateEmpty(char *path, size_t size);
extern int    syslibFileCreateFileSystemExt4(char *path);
extern int    syslibDeviceMount(char *dev, char *path);
extern int    syslibDeviceUnmount(char *path);
extern int    syslibCryptCreate(const char *path, char *password);
extern int    syslibCryptActivate(const char *path, const char *password, char *device_name, int readonly);
extern int    syslibCryptDeactivate(char *device_name);
extern int    syslibCryptCreateWithExt4(char *path, size_t size, char *password);
extern int    syslibCryptMount(char *device_name, char *path);
extern int    syslibCryptUnmount(char *device_name);
extern int    syslibCryptMkdir(char *path, char *password, char *dir, char *perms);
extern tDirListing syslibCryptList(char *path, char *password, char *dir);
extern int    syslibCryptFileWrite(char *path, char *password, char *fpath, char *data);
extern char * syslibCryptFileRead(char *path, char *password, char *fpath);
extern int    syslibCryptFileCopy(char *path, char *password, char *sourceFile, char *destFile);
extern int    syslibCryptFileMove(char *path, char *password, char *sourceFile, char *destFile);
extern int    syslibCryptFileDelete(char *path, char *password, char *fpath);
extern tCryptSpace syslibCryptGetSpace(char *path, char *password);
extern tDirListing syslibCryptLs(char *path, char *password, char *dir);
extern void   syslibDirListingFree(tDirListing dl);

extern int    syslibRAMDiskCreate(int size, char *path);
extern int    syslibRAMDiskUnmount(int size);

extern char * syslibDBGetType(void);
extern int    syslibDBGetTypeID(void);
extern char  *syslibGetIdentification(void);
extern int    syslibHasCryptLib(void);
extern int    syslibIsPrivileged(void);

extern int    syslibSQLiteInit(void);
extern int    syslibHasSQLite(void);
extern int    syslibSQLiteQuery(char *filename, char *query, int perms);
extern char * syslibSQLiteSelect(char *filename, char *query, int idx, char *def);
extern void   syslibSQLiteSetMessageProcessor(tSQLiteMessageFunc func);
extern void   syslibSQLiteFree(void);

extern int    syslibPQInit(void);
extern int    syslibHasPQLib(void);
extern void   syslibPQSetMessageProcessor(tPQMessageProcesorFunc func);
extern void   syslibPQFree(void);

extern int    syslibMariaInit(void);
extern int    syslibHasMariaLib(void);
extern void   syslibMariaFree(void);

extern void   syslibFree(void);

#endif
