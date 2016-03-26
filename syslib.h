// Various defines
//#define DEBUG

#ifdef DEBUG
#define DEBUG_LIB
#define DEBUG_UTILS
#define DEBUG_DATABASE
#endif

#define	SYSLIB_VERSION		"2016-03-10"
#define	SYSLIB_LOG_PATH		"/var/log/syslib"

#include "aesCryptor.h"

#include <math.h>
#include <time.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <libgen.h>
#include <stdlib.h>
#include <stdarg.h>
#include <signal.h>
#include <malloc.h>
#include <mntent.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/vfs.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/reboot.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/syscall.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <linux/netdevice.h>

#include <sqlite3.h>
#include <dlfcn.h>
#include <termios.h>

#include <libcryptsetup.h>

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

#define INIT_BUFLEN	1024
#define LENTAB		8

#define	CONF_VAR	"SYSLIB_CONFIG"
#define	CONF_FILE	"/etc/syslib.conf"

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

#define	MACHINE_UUID_FILE	"/etc/machine-uuid"
#define	LOG_FILE		"/var/log/syslib.log"
#define	DEBUG_FILE 		"/etc/syslib.debug"

#define	LOG_LEVEL_INFO		0x01
#define	LOG_LEVEL_ERROR		0x02
#define	LOG_LEVEL_WARNING	0x04
#define LOG_LEVEL_VERBOSE	0x08
#define LOG_LEVEL_DEBUG		0x10

#define LOG_LEVEL_ALL           LOG_LEVEL_INFO | LOG_LEVEL_ERROR | LOG_LEVEL_WARNING | LOG_LEVEL_VERBOSE | LOG_LEVEL_DEBUG

typedef int (*tRunFunc) (const char *mp, const char *arg1, const char *arg2);

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

tCryptSpace gCryptSpace;

char gCryptFileData[65536];
int nCryptDirListing;
char **gCryptDirListing;

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

enum {
    TCP_ESTABLISHED = 1,
    TCP_SYN_SENT,
    TCP_SYN_RECV,
    TCP_FIN_WAIT1,
    TCP_FIN_WAIT2,
    TCP_TIME_WAIT,
    TCP_CLOSE,
    TCP_CLOSE_WAIT,
    TCP_LAST_ACK,
    TCP_LISTEN,
    TCP_CLOSING                 /* now a valid state */
};

#define	DB_TYPE_NONE	0x00
#define	DB_TYPE_MYSQL	0x01
#define	DB_TYPE_PGSQL	0x02
#define	DB_TYPE_SQLITE	0x04

/* SQLite functions */
typedef void (*tSQLiteMessageFunc) (char *);
typedef int  (*tSQLiteOpenFunc) (const char *, sqlite3 **);
typedef int  (*tSQLiteExecFunc) (sqlite3 *, const char *, int (*callback)(void*,int,char**,char**), void *, char **);
typedef void (*tSQLiteFreeFunc) (void *);
typedef int  (*tSQLiteCloseFunc)(sqlite3 *);
typedef int  (*tSQLitePrepareFunc) (sqlite3 *, const char *, int, sqlite3_stmt **, const char **);
typedef int  (*tSQLiteStepFunc) (sqlite3_stmt *);
typedef const unsigned char * (*tSQLiteColumnTextFunc) (sqlite3_stmt *, int);
typedef int  (*tSqliteFinalizeFunc) (sqlite3_stmt *);

tSQLiteOpenFunc  sqlite_open;
tSQLiteExecFunc  sqlite_exec;
tSQLiteFreeFunc  sqlite_vfree;
tSQLiteCloseFunc sqlite_close;
tSQLitePrepareFunc sqlite_prepare;
tSQLiteStepFunc  sqlite_step;
tSQLiteColumnTextFunc sqlite_column_text;
tSqliteFinalizeFunc sqlite_finalize;

typedef int  (*tCryptKeyslotAddVK) (struct crypt_device *cd, int keyslot, const char *volume_key, size_t volume_key_size, const char *passphrase, size_t passphrase_size);
typedef int  (*tCryptActivatePP) (struct crypt_device *cd, const char *name, int keyslot, const char *passphrase, size_t passphrase_size, uint32_t flags);
typedef int  (*tCryptStatus) (struct crypt_device *cd, const char *name);
typedef const char * 	(*tCryptDevName) (struct crypt_device *cd);
typedef int (*tCryptLoad) (struct crypt_device *cd, const char *requested_type, void *params);
typedef void (*tCryptFree) (struct crypt_device *cd);
typedef int (*tCryptFormat) (struct crypt_device *cd, const char *type, const char *cipher, const char *cipher_mode, const char *uuid, const char *volume_key, size_t volume_key_size, void *params);
typedef int (*tCryptInit)(struct crypt_device **cd, const char *device);
typedef int (*tCryptInitByName) (struct crypt_device **cd, const char *name);
typedef int (*tCryptDeactivate) (struct crypt_device *cd, const char *name);

tCryptKeyslotAddVK Dcrypt_keyslot_add_by_volume_key;
tCryptActivatePP Dcrypt_activate_by_passphrase;
tCryptStatus Dcrypt_status;
tCryptDevName Dcrypt_get_device_name;
tCryptLoad Dcrypt_load;
tCryptFree Dcrypt_free;
tCryptFormat Dcrypt_format;
tCryptInit Dcrypt_init;
tCryptInitByName Dcrypt_init_by_name;
tCryptDeactivate Dcrypt_deactivate;

#ifdef USE_PGSQL
#include "libpq-fe.h"
typedef void (*PQnoticeProcessor) (void *arg, const char *message);

typedef PQnoticeProcessor (*tPQsetNoticeProcessorFunc) (PGconn *conn, PQnoticeProcessor proc, void *arg);
typedef ConnStatusType (*tPQstatusFunc) (const PGconn *conn);
typedef ExecStatusType (*PQresultStatusFunc) (const PGresult *res);
typedef int (*tPQntuplesFunc) (const PGresult *res);
typedef int (*tPQgetisnullFunc) (const PGresult *res, int row_number, int column_number);
typedef PGresult * (*tPQexecFunc) (PGconn *conn, const char *command);
typedef PGconn * (*tPQconnectdbFunc) (const char *conninfo);
typedef char * (*tPQfnameFunc) (const PGresult *res, int column_number);
typedef void (*tPQfinishFunc) (PGconn *conn);
typedef char * (*tPQerrorMessageFunc) (const PGconn *conn);
typedef int (*tPQnfieldsFunc) (const PGresult *res);
typedef char * (*tPQgetvalueFunc) (const PGresult *res, int row_number, int column_number);
typedef void (*tPQclearFunc)(PGresult *res);

/* PostgreSQL functions */
tPQsetNoticeProcessorFunc dPQsetNoticeProcessor;
tPQstatusFunc dPQstatus;
PQresultStatusFunc dPQresultStatus;
PQresultStatusFunc dPQntuples;
tPQgetisnullFunc dPQgetisnull;
tPQexecFunc dPQexec;
tPQconnectdbFunc dPQconnectdb;
tPQfnameFunc dPQfname;
tPQfinishFunc dPQfinish;
tPQerrorMessageFunc dPQerrorMessage;
tPQnfieldsFunc dPQnfields;
tPQgetvalueFunc dPQgetvalue;
tPQclearFunc dPQclear;
#endif

/* MySQL/MariaDB functions */
#ifdef USE_MARIADB
#include <mysql/mysql.h>

typedef MYSQL * (*tMySQLInitFunc)(MYSQL * mysql);
typedef const char * (*tMySQLInfoFunc)(MYSQL * mysql);
typedef unsigned long (*tMySQLSerVerFunc)(MYSQL * mysql);
typedef void (*tMySQLClose) (MYSQL * mysql);
typedef my_ulonglong (*tMySQLAffectedRows)(MYSQL * mysql);
typedef int (*tMySQLRealQuery)(MYSQL * mysql, const char * q, unsigned long);
typedef unsigned int (*tMySQLNumFields)(MYSQL_RES * );
typedef MYSQL_RES * (*tMySQLStoreResult)(MYSQL * mysql);
typedef void (*tMySQLFreeResult)(MYSQL_RES * result);
typedef int (*tMySQLPing)(MYSQL * mysql);
typedef MYSQL * (*tMySQLRealConnect)(MYSQL * mysql, const char * host, const char * user, const char * passwd, const char * db,
		unsigned int port, const char * unix_socket, unsigned long flags);
typedef unsigned long (*tMySQLRealEscapeString)(MYSQL * mysql, char * to, const char * from, unsigned long);
typedef int (*tMySQLSelectDB)(MYSQL * mysql, const char * db);
typedef const char * (*tMySQLStat)(MYSQL * mysql);
typedef MYSQL_ROW (*tMySQLFetchRow)(MYSQL_RES * result);
typedef unsigned long * (*tMySQLFetchLengths)(MYSQL_RES * result);
typedef unsigned int (*tMySQLThreadSafe)(void );

tMySQLInitFunc dMySQL_init;
tMySQLInfoFunc dMySQL_info;
tMySQLStat dMySQL_error;
tMySQLSerVerFunc dMySQL_server_version;
tMySQLAffectedRows dMySQL_affected_rows;
tMySQLRealQuery dMySQL_real_query;
tMySQLNumFields dMySQL_num_fields;
tMySQLStoreResult dMySQL_store_result;
tMySQLFreeResult  dMySQL_free_result;
tMySQLPing     dMySQL_ping;
tMySQLRealConnect dMySQL_real_connect;
tMySQLRealEscapeString dMySQL_real_escape_string;
tMySQLFetchRow dMySQL_fetch_row;
tMySQLSelectDB dMySQL_select_db;
tMySQLStat     dMySQL_stat;
tMySQLThreadSafe dMySQL_thread_safe;
tMySQLFetchLengths dMySQL_fetch_lengths;
tMySQLClose    dMySQL_close;
#endif

// MODIFY SYSLIB.C TO CHECK WHETHER IT IS NULL OR NOT TO PREVENT SIGSEGV! + insert MySQL too
// Then create API like database{Select|Execute}(type, type_args, query); with type = DATABASE_MYSQL, DATABASE_PGSQL, DATABASE_SQLITE
// with appropriate type_args - connection string like "type://hostname/database?user=user&password=password" (or "sqlite:///path/to/file")

tInstance *instances;
int nInstances;
tSQLiteMessageFunc gSMP;
PQnoticeProcessor gSMP_pq;
void *_sqliteLib;
void *_libpq;
void *_libmaria;
void *_cryptLib;

int _hasSQLite;
int _hasPQLib;
int _hasMariaLib;
int _hasCrypt;

/* Thread-safe handling */
void _syslibSetDBConn(char *dbconn);
char *_syslibGetDBConn(void);
void _syslibSetDBConnPtr(void *ptr);
void *_syslibGetDBConnPtr(void);
void _syslibSetInitDone(int init);
int _syslibGetInitDone(void);

static pthread_mutex_t cs_mutex =  PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t csf_mutex =  PTHREAD_MUTEX_INITIALIZER;

/* Just some prototypes */
char *confGet(char *key);
void confDump(void);
void pqCleanup(void);
char *get_datetime(void);

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
void freeQueryResult(tQueryResult r);
int pqExecute(char *query);

MYSQL *_syslibMariaDBConnect(char *connstr);

// config.c
typedef struct tConfigValue {
	char *name;
	char *value;
	int aes128enc;
} tConfigValue;

typedef struct tCV {
	char *key;
	char *value;
} tCV;

tCV *_confVars;
int _nConfVars;

int _configLoaded;
tConfigValue *_configValues;
int _nConfigValues;

int _configLoad(char *fn);
tConfigValue configGet(char *name);
char *configGetValue(char *name);
void _configDump(void);
void _configFree(void);

int serviceRestartIfNotRunning(char *name, int maxRetries);
void serviceRestartSystemd(char *name);
int pgSQLNotRunning(void);

unsigned long long getMemoryTotal(void);
unsigned long long getMemoryUsed(void);
unsigned long long getMemoryFree(void);
unsigned long long getMemoryUsedKernel(void);
unsigned long long getMemoryUsedUserspace(void);
unsigned long long getMemoryCache(void);
unsigned long long getMemoryBuffers(void);
char *preventNull(char *str1, char *str2, char *defstr);
int processSuricataAction(char *action);
void serviceCommand(char *name, char *command);

int getMemory(unsigned long long *memTotal, unsigned long long *memFree, unsigned long long *memUsed,
        unsigned long long *memKernel, unsigned long long *memUserspace, unsigned long long *memBuffers,
        unsigned long long *memCache, unsigned long long *swapFree, unsigned long long *swapUsed);

char *getCommandOutput(char *cmd, int ignoreStderr, int newUid);
int getCommandOutputSize(char *cmd, int ignoreStderr, int newUid);
char *getMACAddress(char *iface);

/* Internal prototypes */
long _gettid(void);
int _syslibGetCurrent(void);
int pqConnect(char *connstr, PGconn *conn);
void _syslibConfCriticalSectionEnter(void);
void _syslibConfCriticalSectionLeave(void);
void _syslibEnsureConnection(void);
char *_syslibMariaDBSelect(char *query, int idx);

/* Public functions */
extern int    syslibInit(char *key, char *appname);
extern void   syslibSetBTHandlers(void);
extern pid_t  syslibGetParentPID(pid_t pid);
extern char * syslibGetProcessName(pid_t pid);
extern char * syslibGetProcessTree(pid_t pid);
extern int    syslibSetLogging(char *debugFile, int flags);
extern void   syslibDebugDump(void);
extern char * syslibSystemUUID(void);
extern int    syslibEnsureUUIDFile(void);
extern char * syslibGetShortHostName(void);
extern unsigned int syslibConvertTimestampToUnix(char *ts);
extern char * syslibQueryGetSingle(char *table, char *field, char *sensor, char *conditionAppend, char *def);
extern char **syslibQueryGetArray(char *table, char *field, int *out, char *sensor, char *conditionAppend);
extern int    syslibGetVersion(int *major, int *minor, int *micro);
extern char * syslibGetRevision(void);
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
extern int    syslibSSHUserLoginMessageSet(char *user, time_t tsFrom, time_t tsTo, char *msg);
extern char * syslibSSHUserLoginMessageGet(char *user, time_t ts);
extern int    syslibCheckRunningAsShell(void);

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
extern tCryptSpace syslibCryptGetSpace(char *path, char *password);
extern tDirListing syslibCryptLs(char *path, char *password, char *dir);
extern void   syslibDirListingFree(tDirListing dl);

extern int    syslibSQLiteInit(void);
extern int    syslibHasSQLite(void);
extern int    syslibSQLiteQuery(char *filename, char *query, int perms);
extern char * syslibSQLiteSelect(char *filename, char *query, int idx, char *def);
extern void   syslibSQLiteSetMessageProcessor(tSQLiteMessageFunc func);
extern void   syslibSQLiteFree(void);

extern int    syslibHasCryptLib(void);
extern int    syslibIsPrivileged(void);

extern char * syslibDBGetType(void);
extern int    syslibDBGetTypeID(void);
extern char  *syslibGetIdentification(void);

extern void   syslibDBConnectorDump(void);

extern int    syslibPQInit(void);
extern int    syslibHasPQLib(void);
extern void   syslibPQSetMessageProcessor(PQnoticeProcessor func);
extern void   syslibPQFree(void);

extern int    syslibMariaInit(void);
extern int    syslibHasMariaLib(void);
extern void   syslibMariaFree(void);

extern void   syslibFree(void);

extern int   syslibQueryExecute(char *connstr);
