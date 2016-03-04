#include "syslib.h"
#include "version_rev.h"

//#define DEBUG_LIB
//#define DEBUG_LIB_CS
//#define ENABLE_CONF_DUMP
//#define ALLOW_OUTPUT

#ifdef DEBUG_LIB
#define DPRINTF(fmt, ...) \
do { fprintf(stderr, "[debug/syslib  ] " fmt , ## __VA_ARGS__); } while (0)
#ifdef DEBUG_LIB_CS
	#define DPRINTF_CS(fmt, ...) \
	do { fprintf(stderr, "[debug/syslibcs] " fmt , ## __VA_ARGS__); } while (0)
#else
	#define DPRINTF_CS(fmt, ...) \
	do {} while(0)
#endif
#else
#define DPRINTF(fmt, ...) \
do {} while(0)
#define DPRINTF_CS(fmt, ...) \
do {} while(0)
#endif

#define MACHINE_UUID_FILE       "/etc/machine-uuid"
#define SSH_STATE_FILE		"/etc/ssh-enabled"
#define SSH_STATE_FILE_USER	"/etc/ssh-per-user.db"
#define PROFILE_USER_LOGIN	"/etc/profile.d/user-login.sh"

char *gSSHUserStateFile = NULL;
char *gLocalizationPath = NULL;

typedef struct tTPids {
	int num;
	int *pid;
	char **name;
} tTPids;

/* Logging implementation */

/**
 * Gets the debug level for library invocation
 *
 * @return Debug level read from the DEBUG_FILE
 */
int getDebugLevel(void)
{
	int i, ret = 0;
	char line[1024] = { 0 };

	// Acceptable format: info|warning|error|verbose|debug
	FILE *fp = fopen(DEBUG_FILE, "r");
	if (fp == NULL)
		return LOG_LEVEL_INFO | LOG_LEVEL_WARNING | LOG_LEVEL_ERROR;

	fgets(line, sizeof(line), fp);
	if (line[strlen(line) - 1] == '\n')
		line[strlen(line) - 1] = 0;
	fclose(fp);

	tTokenizer t = tokenize(line, "|");

	for (i = 0; i < t.numTokens; i++) {
		if (strcmp(t.tokens[i], "all") == 0)
			ret |= LOG_LEVEL_INFO | LOG_LEVEL_ERROR | LOG_LEVEL_WARNING | LOG_LEVEL_VERBOSE | LOG_LEVEL_DEBUG;
		else
		if (strcmp(t.tokens[i], "info") == 0)
			ret |= LOG_LEVEL_INFO;
		else
		if (strcmp(t.tokens[i], "error") == 0)
			ret |= LOG_LEVEL_ERROR;
		else
		if (strcmp(t.tokens[i], "warning") == 0)
			ret |= LOG_LEVEL_WARNING;
		else
		if (strcmp(t.tokens[i], "verbose") == 0)
			ret |= LOG_LEVEL_VERBOSE;
		else
		if (strcmp(t.tokens[i], "debug") == 0)
			ret |= LOG_LEVEL_DEBUG;
	}

	tokensFree(t);

	return ret;
}

/**
 * Check whether debug is enabled for specified level
 *
 * @param level required level to check against
 * @return boolean false for level disabled, true for level enabled
 */
int isDebugEnabled(int level)
{
	int ret = 0;
	int id = _syslibGetCurrent();

	if (id < 0)
		return 0;

	int gLevel = instances[id].debugFlags;
	//printf("gLevel: %d ?= %d\n", ((gLevel & LOG_LEVEL_INFO) != 0), level);
	if (((gLevel & LOG_LEVEL_INFO) != 0) && (level == LOG_LEVEL_INFO)) {
		//printf("Found debug level: info\n");
		ret = 1;
	}
	else
	if (((gLevel & LOG_LEVEL_ERROR) != 0) && (level == LOG_LEVEL_ERROR)) {
		//printf("Found debug level: error\n");
		ret = 1;
	}
	else
	if (((gLevel & LOG_LEVEL_WARNING) != 0) && (level == LOG_LEVEL_WARNING)) {
		//printf("Found debug level: warning\n");
		ret = 1;
	}
	else
	if (((gLevel & LOG_LEVEL_VERBOSE) != 0) && (level == LOG_LEVEL_VERBOSE)) {
		//printf("Found debug level: verbose\n");
		ret = 1;
	}
	else
	if (((gLevel & LOG_LEVEL_DEBUG) != 0) && (level == LOG_LEVEL_DEBUG)) {
		//printf("Found debug level: debug\n");
		ret = 1;
	}

	return ret;
}

/**
 * Log string to file LOG_FILE
 *
 * @param str string to be logged
 * @return None
 */
void _xlogToFile(char *str)
{
        FILE *fp = fopen(LOG_FILE, "a");
        if (fp == NULL)
		return;
        fprintf(fp, "%s", str);
	fclose(fp);
}

/**
 * Log formatted string to set debug log file
 *
 * @param level   logging level string applies to
 * @param fmt     vfprintf() formatting string
 * @param VA_ARGS arguments for vfprintf()
 * @return None
 */
void logWrite(int level, const char *fmt,...)
{
	int id = _syslibGetCurrent();
	char dlFile[1024] = { 0 };

	if (id < 0)
		return;

	if (instances[id].debugFile == NULL)
		return;

	snprintf(dlFile, sizeof(dlFile), "%s/%s", SYSLIB_LOG_PATH, instances[id].debugFile);

	if (!isDebugEnabled(level))
		return;

	va_list arglist;
	FILE *fp = fopen(dlFile, "a");
	if (fp == NULL)
		return;

	char *tmp = get_datetime();

	if (level == LOG_LEVEL_INFO)
		fprintf(fp, "[%s TID #%d] [INFO   ] ", tmp, _gettid());
	else
	if (level == LOG_LEVEL_ERROR)
                fprintf(fp, "[%s TID #%d] [ERROR  ] ", tmp, _gettid());
        else
	if (level == LOG_LEVEL_WARNING)
                fprintf(fp, "[%s TID #%d] [WARNING] ", tmp, _gettid());
        else
	if (level == LOG_LEVEL_VERBOSE)
                fprintf(fp, "[%s TID #%d] [VERBOSE] ", tmp, _gettid());
        else
	if (level == LOG_LEVEL_DEBUG)
                fprintf(fp, "[%s TID #%d] [DEBUG  ] ", tmp, _gettid());

	va_start( arglist, fmt );
	vfprintf( fp, fmt, arglist );
	va_end( arglist );

	free(tmp);

	fflush(fp);
	fclose(fp);
}
/* End of logging implementation */

/**
 * Internal memory allocation code for syslib
 *
 * @param size    memory size to be allocated
 * @return pointer a newly allocated memory block
 */
void *_syslibAlloc(size_t size)
{
	void *ret = NULL;

	ret = malloc(size);
	if (ret == NULL)
		DPRINTF("%s(%d) allocated failed to allocate %d bytes\n", __FUNCTION__, size, size);
	else
		DPRINTF("%s(%d) allocated %d bytes at %p\n", __FUNCTION__, size, size, ret);

	return ret;
}

/**
 * Internal memory reallocation code for syslib
 *
 * @param ptr     original memory pointer for reallocation
 * @param size    memory size to be reallocated
 * @return pointer a newly allocated memory block
 */
void *_syslibRealloc(void *ptr, size_t size)
{
	void *ret = NULL;

	DPRINTF("%s: Reallocating %p to %d bytes\n",
		__FUNCTION__, ptr, size);
	ret = realloc(ptr, size);
	DPRINTF("%s: Reallocation returned pointer %p\n",
		__FUNCTION__, ret);
	return ret;
}

/**
 * Internal memory free function
 *
 * @param  ptr pointer to be freed
 * @return None
 */
void _syslibFree(void *ptr)
{
	DPRINTF("%s: Freeing %p\n", __FUNCTION__, ptr);

	if (ptr != NULL)
		free(ptr);
}


/**
 * Internal check for function zombie connections from pg_stat_activity table
 *
 * @return None
 */
void _syslibHandleZombies(void)
{
	tQueryResult ret;
	int numVars = 1;
	char **vars = NULL;
	char *appName = NULL;
	char query[4096] = { 0 };

	char *tmp = _syslibGetDBConn();
	if (tmp != NULL) {
		int i;

		tTokenizer t = tokenize(tmp, "&");
		for (i = 0; i < t.numTokens; i++) {
			if (strncmp(t.tokens[i], "application_name=", 17) == 0)
				appName = strdup(t.tokens[i] + 17);
		}
		tokensFree(t);
	}
	free(tmp);

	if (appName == NULL)
		return;

	snprintf(query, sizeof(query), "SELECT pid FROM pg_stat_activity WHERE query = '' AND application_name = '%s';", appName);

	int i;
	vars = (char **)malloc( sizeof(char *) );
	vars[0] = strdup("pid");
	ret = pqSelectAdvanced(query, numVars, vars);
	if (ret.nRows > 5) {
		for (i = 0; i < ret.nRows; i++) {
			kill( atoi(ret.rows[i].fields[0].val), SIGKILL);
		}
	}

	free(appName);
	freeQueryResult(ret);
	free(vars[0]);
	free(vars);

	DPRINTF("%s: Query '%s' returned '%s' [TID #%d]\n",
		__FUNCTION__, query, ret, _gettid());
	logWrite(LOG_LEVEL_DEBUG, "%s: Query '%s' returned '%s' [TID #%d]\n",
		__FUNCTION__, query, ret, _gettid());

	syslibQueryResultFree(ret);
}

typedef void InfoHandler(int, siginfo_t *, void *);

/*
 * Signal handler for SIGABRT
 *
 * @param sig signal number
 * @param info process signal information
 * @param vp   dummy argument
 * @return None
 */
void _sighandler_bt(int sig, siginfo_t* info, void* vp)
{
	char tmp[1024] = { 0 };
	int pid = getpid();

	if ((sig == SIGABRT) || (sig == SIGSEGV)) {
		char fn[1024] = { 0 };
		char buf[1024] = { 0 };
		char cmd[1024] = { 0 };

		snprintf(tmp, sizeof(tmp), "/proc/%d/cmdline", pid);
		FILE *fp = fopen(tmp, "r");
		if (fp != NULL) {
			fgets(buf, sizeof(buf), fp);
			fclose(fp);
		}
		else
			strcpy(buf, "unknown");

		snprintf(fn, sizeof(fn), "/tmp/backtrace-%d", time(NULL));
		snprintf(tmp, sizeof(tmp), "echo \"Binary: %s. PID: %d\" > %s", buf, pid, fn);
		system(tmp);
		snprintf(cmd, sizeof(cmd), "gdb -p %d --batch -ex \"thread apply all bt full\"", pid);
		snprintf(tmp, sizeof(tmp), "echo \"Command: %s\" >> %s; echo >> %s", cmd, fn, fn);
		system(tmp);
		snprintf(tmp, sizeof(tmp), "%s >> %s 2> /dev/null", cmd, fn);
		system(tmp);
		if (access(fn, F_OK) == 0) {
			snprintf(tmp, sizeof(tmp), "logger -t \"%s[%d]\" \"Backtrace saved to %s\"", buf, pid, fn);
			system(tmp);
		}
		exit(0);
	}
}

/*
 *  Introduce signal handler with information
 *
 *  @param signum  signal to handle
 *  @param handler handler to process signal
 *  @return old handler
 */
InfoHandler*
_syslibSignalWithInfo(int signum, InfoHandler* handler)
{
	struct sigaction action, old_action;

	memset(&action, 0, sizeof(struct sigaction));
	action.sa_sigaction = handler;
	sigemptyset(&action.sa_mask); /* block sigs of type being handled */
	action.sa_flags = SA_RESTART|SA_SIGINFO; /* restart syscalls if possible */

	sigaction(signum, &action, &old_action);
	return (old_action.sa_sigaction);
}

/**
 * Get parent process ID for PID
 *
 * @param pid process to get it's parent PID
 * @return process parent pid
 */
pid_t syslibGetParentPID(pid_t pid)
{
	FILE *fp = NULL;
	char pd[128] = { 0 };
	char cmd[1024] = { 0 };
	int ret = 0;

	snprintf(cmd, sizeof(cmd), "/proc/%d/status", pid);
	if (access(cmd, R_OK) != 0)
		return 0;

	fp = fopen(cmd, "r");
	if (fp == NULL)
		return 0;

	while (!feof(fp)) {
		fgets(pd, sizeof(pd), fp);
		if (strncmp(pd, "PPid:", 5) == 0) {
			ret = atoi(pd + 6);
		}
	}
	fclose(fp);

	return ret;
}

/**
 * Get process name
 *
 * @param pid process to get it's name
 * @return process name
 */
char *syslibGetProcessName(pid_t pid)
{
	FILE *fp = NULL;
	char pd[1024] = { 0 };
	char cmd[1024] = { 0 };

	snprintf(cmd, sizeof(cmd), "/proc/%d/cmdline", pid);
	if (access(cmd, R_OK) != 0)
		return NULL;

	fp = fopen(cmd, "r");
	if (fp == NULL)
		return 0;
	fgets(pd, sizeof(pd), fp);
	fclose(fp);

	return strdup(pd);
}

/**
 * Get process tree
 *
 * TODO: Rewrite to support formatting like "[PID %p] %n" where %p is PID and %n is process name [!!!]
 *
 * @param pid process to get it's process tree
 * @return process tree as string
 */
char *syslibGetProcessTree(pid_t pid)
{
	int j, i = 0;
	char *tmp = NULL;
	char tmps[1024] = { 0 };
	char ret[8192] = { 0 };
	tTPids tp;

	tp.num = 15;
	tp.pid = (int *)malloc( tp.num * sizeof(int) );
	tp.name = (char **)malloc( tp.num * sizeof(char *) );

	while (pid > 0) {
		tmp = syslibGetProcessName(pid);
		tp.pid[i] = pid;
		tp.name[i] = tmp;
		i++;

		pid = syslibGetParentPID(pid);
	}

	for (j = i - 1; j >= 0; j--) {
		if (tp.name[j] != NULL)
			snprintf(tmps, sizeof(tmps), "%s [PID %d] => ", tp.name[j], tp.pid[j]);
		else
			snprintf(tmps, sizeof(tmps), "[PID %d] => ", tp.pid[j]);

		strcat(ret, tmps);
	}

	ret[strlen(ret) - 4] = 0;

	for (j = 0; j < i; j++)
		free(tp.name[j]);
	free(tp.name);
	free(tp.pid);

	return strdup(ret);
}

/*
 * Initialize SIGABRT and SIGSEGV handlers
 *
 * @return None
 */
void syslibSetBTHandlers(void)
{
	_syslibSignalWithInfo(SIGABRT, _sighandler_bt);
	_syslibSignalWithInfo(SIGSEGV, _sighandler_bt);
}

/**
 * Internal ID getter function for specified thread ID
 *
 * @param  tid thread id
 * @return identifier in the instances structure
 */
int _syslibGetID(long tid)
{
	int i = 0;

	for (i = 0; i < nInstances; i++) {
		if (instances[i].id == tid)
			return i;
	}

	return -1;
}

/**
 * Critical section entry point
 *
 * @return None
 */
void _syslibCriticalSectionEnter(void)
{
	int ret;

	DPRINTF("%s: Entering critical section [TID #%d]\n",
		__FUNCTION__, _gettid() );
	ret = pthread_mutex_lock( &cs_mutex );
	DPRINTF("%s: Lock returned %d [TID #%d]\n",
		__FUNCTION__, ret, _gettid() );
}

/**
 * Critical section exit point
 *
 * @return None
 */
void _syslibCriticalSectionLeave(void)
{
	int ret;

	DPRINTF("%s: Leaving critical section [TID #%d]\n",
		__FUNCTION__, _gettid() );
	ret = pthread_mutex_unlock( &cs_mutex );
	DPRINTF("%s: Unlock returned %d [TID #%d]\n",
		__FUNCTION__, ret, _gettid() );
}

/**
 * Configuration file critical section entry point
 *
 * @return None
 */
void _syslibConfCriticalSectionEnter(void)
{
	int ret;

	 DPRINTF("%s: Entering critical section for config [TID #%d]\n",
		__FUNCTION__, _gettid() );
	ret = pthread_mutex_lock( &csf_mutex );
	DPRINTF("%s: Lock returned %d [TID #%d]\n",
		__FUNCTION__, ret, _gettid() );
}

/**
 * Configuration file critical section exit point
 *
 * @return None
 */
void _syslibConfCriticalSectionLeave(void)
{
	int ret;

	DPRINTF("%s: Leaving critical section for config [TID #%d]\n",
		__FUNCTION__, _gettid() );
	ret = pthread_mutex_unlock( &csf_mutex );
	DPRINTF("%s: Unlock returned %d [TID #%d]\n",
		__FUNCTION__, ret, _gettid() );
}

/**
 * New structure entry memory allocation
 *
 * @param  tid         thread ID
 * @param  dbconn      database connection string
 * @param  dbconnptr   database connection pointer
 * @param  initdone    initialization done flag
 * @param  debugFile   debug file to be associated with the structure entry
 * @param  debugFlags  debug flags to be associated with the structure entry
 * @return Newly allocated entry ID
 */
int _syslibEntryAlloc(long tid, char *dbconn, void *dbconnptr, int initdone, char *debugFile, int debugFlags)
{
	int ret;

	DPRINTF("%s: Called with tid = %ld, dbconn = %s, dbconnptr = %p, initdone = %d, debugFile = %s, debugFlags = %d\n",
		__FUNCTION__, tid, dbconn, dbconnptr, initdone, debugFile, debugFlags);

//	DPRINTF_CS("%s: About to enter critical section [TID #%d]\n", __FUNCTION__, _gettid() );
//	_syslibCriticalSectionEnter();
//	DPRINTF_CS("%s: Critical section entered [TID #%d]\n", __FUNCTION__, _gettid() );

	// Handle a critical section in alloc/dealloc/entry swap
	if (instances == NULL)
		instances = (tInstance *)_syslibAlloc( sizeof(tInstance) );
	else
		instances = (tInstance *)_syslibRealloc(instances,
				(nInstances + 1) * sizeof(tInstance) );

	if (instances == NULL) {
		ret = -ENOMEM;
		goto cleanup;
	}

	if ((dbconn == NULL) && (dbconnptr == NULL) && (initdone == 0) && (debugFile == NULL) && (debugFlags == 0)) {
		DPRINTF("%s: Invalid arguments, exiting ...\n", __FUNCTION__);
		ret = -EINVAL;
		goto cleanup;
	}

	instances[nInstances].id = tid;
	instances[nInstances].dbconn = (dbconn == NULL) ? NULL : strdup(dbconn);
	instances[nInstances].dbconnptr = (dbconnptr == NULL) ? NULL : dbconnptr;
	instances[nInstances].initdone = initdone;
	instances[nInstances].debugFile = (debugFile == NULL) ? NULL : debugFile;
	instances[nInstances].debugFlags = (debugFlags == -1) ? getDebugLevel() : debugFlags;
	nInstances++;

	DPRINTF("%s: Added new entry to instance list [count is %d, TID #%d]\n",
		__FUNCTION__, nInstances, _gettid() );

	ret = nInstances - 1;

	DPRINTF("%s: Allocated new entry (ID = %d: { tid: %d, dbconn: '%s', ptr: %p, initdone: %d }\n",
		__FUNCTION__, nInstances - 1, tid, dbconn, dbconnptr, initdone);

cleanup:
//	DPRINTF_CS("%s: About to leave critical section [TID #%d]\n", __FUNCTION__, _gettid() );
//	_syslibCriticalSectionLeave();
//	DPRINTF_CS("%s: Critical section left [TID #%d]\n", __FUNCTION__, _gettid() );

	return ret;
}

/**
 * Pointer validation to stay within allowed memory region
 *
 * @param  ptr         pointer
 * @param  changed     output integer/boolean specifying whether change occurred or not
 * @return New pointer
 */
void *_syslibValidatePointer(void *ptr, int *changed)
{
	char tmp[16] = { 0 };

	if (changed != NULL)
		*changed = 0;

	if (ptr == NULL)
		return ptr;

	snprintf(tmp, sizeof(tmp), "%p", ptr);
	int x = strtol(tmp, NULL, 16);

	//DPRINTF("%s: Pointer points to '%s'\n", __FUNCTION__, tmp);

	if (x < 0xFFFF) {
		if (changed != NULL)
			*changed = 1;
		ptr = NULL;
	}

	return ptr;
}

/**
 * Pointer fix for all entries in the instances structure
 *
 * @return None
 */
void _syslibPointerFix(void)
{
	int i, c1, c2, rd = 0;

	if ((nInstances == 0) || (instances == NULL))
		return;

	for (i = 0; i < nInstances; i++) {
		instances[i].dbconn = _syslibValidatePointer(instances[i].dbconn, &c1);
		instances[i].dbconnptr = _syslibValidatePointer(instances[i].dbconnptr, &c2);

		if (c1 || c2) {
			DPRINTF("%s: Fixed pointers for #%d\n", __FUNCTION__, i);
			rd++;
		}
	}

	if (rd > 0)
		DPRINTF("%s: Fixer fixed %d entry/entries\n", __FUNCTION__, rd);
}

/**
 * Structure entry dump code
 *
 * @param  i          index in the instances structure
 * @param  inst       instance entry
 * @param  dumpToLog  boolean to determine destination of the dump => 0 for debug output (if enabled), 1 as log file output
 * @return None
 */
void _syslibDumpInstance(int i, tInstance inst, int dumpToLog)
{
	int c;

	inst.dbconn = _syslibValidatePointer(inst.dbconn, &c);

	if (dumpToLog) {
		logWrite(LOG_LEVEL_INFO, "Dumping instance information #%d:\n", i);
		logWrite(LOG_LEVEL_INFO, "\tID:            %d\n", inst.id);
		logWrite(LOG_LEVEL_INFO, "\tDBConnStr ptr: %p (fixed %d)\n", inst.dbconn, c);
		logWrite(LOG_LEVEL_INFO, "\tDBConnStr val: %s\n", inst.dbconn);
		logWrite(LOG_LEVEL_INFO, "\tDBConnPtr:     %p\n", inst.dbconnptr);
		logWrite(LOG_LEVEL_INFO, "\tInitDone:      %d\n", inst.initdone);
		logWrite(LOG_LEVEL_INFO, "\tDebug file:    %s\n", inst.debugFile);
		logWrite(LOG_LEVEL_INFO, "\tDebug flags:   %d\n", inst.debugFlags);
	}
	else {
		DPRINTF("Dumping instance information #%d:\n", i);
		DPRINTF("\tID:            %d\n", inst.id);
		DPRINTF("\tDBConnStr ptr: %p (fixed %d)\n", inst.dbconn, c);
		DPRINTF("\tDBConnStr val: %s\n", inst.dbconn);
		DPRINTF("\tDBConnPtr:     %p\n", inst.dbconnptr);
		DPRINTF("\tInitDone:      %d\n", inst.initdone);
		DPRINTF("\tDebug file:    %s\n", inst.debugFile);
		DPRINTF("\tDebug flags:   %d\n", inst.debugFlags);
	}
}

/**
 * Dump all entries in the instances structure
 *
 * @param  dumpToLog  boolean to determine destination of the dump => 0 for debug output (if enabled), 1 as log file output
 * @return None
 */
void _syslibDumpInstances(int dumpToLog)
{
	if ((nInstances == 0) || (instances == NULL))
		return;

	int i;
	for (i = 0; i < nInstances; i++)
		_syslibDumpInstance(i, instances[i], dumpToLog);
}

/**
 * Swap two entries in the instances structure
 *
 * @param  id1   first entry ID
 * @param  id2   second entry ID
 * @return None
 */
void _syslibEntrySwap(int id1, int id2)
{
	tInstance i1, i2;

	if (id1 == id2)
		return;

	DPRINTF("%s: Swapping entries #%d and #%d (i[%d] = i[%d])\n", __FUNCTION__, id1, id2, id1, id2);

	if (instances == NULL) {
		DPRINTF("%s: Instances pointer is NULL\n", __FUNCTION__);
		return;
	}

	int c;
	char *dbconn = NULL;

	_syslibDumpInstance(-1, instances[id1], 0);

	i1.id = instances[id1].id;
	dbconn = _syslibValidatePointer(instances[id1].dbconn, &c);
	i1.dbconn = (dbconn == NULL) ? NULL : strdup(dbconn);
	i1.dbconnptr = (instances[id1].dbconnptr == NULL) ? NULL : instances[id1].dbconnptr;
	i1.debugFile = (instances[id1].debugFile == NULL) ? NULL : instances[id1].debugFile;
	i1.debugFlags = instances[id1].debugFlags;
	i1.initdone = instances[id1].initdone;

	_syslibDumpInstance(-1, instances[id2], 0);

	i2.id = instances[id2].id;
	dbconn = _syslibValidatePointer(instances[id2].dbconn, &c);
	i2.dbconn = (dbconn == NULL) ? NULL : strdup(dbconn);
	i2.dbconnptr = (instances[id2].dbconnptr == NULL) ? NULL : instances[id2].dbconnptr;
	i1.debugFile = (instances[id2].debugFile == NULL) ? NULL : instances[id2].debugFile;
	i2.debugFlags = instances[id2].debugFlags;
	i2.initdone = instances[id2].initdone;

	if (id1 == id2)
		return;

	DPRINTF("%s: ID #%d = { id: %d, dbconn: '%s', dbconnptr: %p, initdone: %d }\n",
		__FUNCTION__, id1, i1.id, i1.dbconn, i1.dbconnptr, i1.initdone);

	DPRINTF("%s: ID #%d = { id: %d, dbconn: '%s', dbconnptr: %p, initdone: %d }\n",
		__FUNCTION__, id2, i2.id, i2.dbconn, i2.dbconnptr, i2.initdone);

	instances[id1].id = i2.id;
	instances[id1].dbconn = i2.dbconn;
	instances[id1].dbconnptr = i2.dbconnptr;
	instances[id1].initdone = i2.initdone;
	instances[id1].debugFile = i2.debugFile;
	instances[id1].debugFlags = i2.debugFlags;
	instances[id2].id = i1.id;
	instances[id2].dbconn = i1.dbconn;
	instances[id2].dbconnptr = i1.dbconnptr;
	instances[id2].initdone = i1.initdone;
	instances[id2].debugFile = i1.debugFile;
	instances[id2].debugFlags = i1.debugFlags;
}

/**
 * Deallocate memory for entry in the instance structure
 *
 * @param  tid   thread ID to deallocate for
 * @return errno value
 */
int _syslibEntryDealloc(long tid)
{
	int id = _syslibGetID(tid);

	if (id < 0) {
		DPRINTF("%s: Cannot find entry with TID #%d\n",
			__FUNCTION__, tid);
		return -ENOENT;
	}

	DPRINTF_CS("%s: About to enter critical section [TID #%d]\n", __FUNCTION__, _gettid() );
	_syslibCriticalSectionEnter();
	DPRINTF_CS("%s: Critical section entered [TID #%d]\n", __FUNCTION__, _gettid() );

	_syslibPointerFix();

	DPRINTF("%s: Dumping instance to dealloc [TID #%d]\n", __FUNCTION__, _gettid() );
	_syslibDumpInstance(-1, instances[id], 0);
	DPRINTF("%s: Dumping instance to dealloc 2 [TID #%d]\n", __FUNCTION__, _gettid() );
	_syslibDumpInstance(-1, instances[nInstances - 1], 0);

	DPRINTF("%s: Deallocating entry #%d [TID #%d]\n",
		__FUNCTION__, id, tid );

	_syslibPointerFix();
	_syslibEntrySwap(id, nInstances - 1);
	_syslibPointerFix();

	_syslibDumpInstance(-1, instances[id], 0);
	_syslibDumpInstance(-1, instances[nInstances - 1], 0);

	_syslibFree(instances[nInstances - 1].dbconn);
	_syslibFree(instances[nInstances - 1].debugFile);

	if (instances[id].dbconnptr == instances[nInstances - 1].dbconnptr) {
		instances[id].dbconnptr = instances[nInstances - 1].dbconnptr;
	}
	else {
		if (dPQfinish != NULL) {
			dPQfinish(instances[nInstances - 1].dbconnptr);
			_syslibFree(instances[nInstances - 1].dbconnptr);
			instances[nInstances - 1].dbconnptr = NULL;
		}
	}

	instances[nInstances - 1].dbconn = NULL;
	_syslibPointerFix();

	DPRINTF("%s: Entry #%d deallocated [TID #%d]\n",
		 __FUNCTION__, id, tid);

	nInstances--;
	if (nInstances > 0) {
		int nextSize;

		DPRINTF("%s: Instance count is %d\n", __FUNCTION__, nInstances);

		nextSize = nInstances * sizeof(tInstance);
		DPRINTF("%s: Next size is %d\n", __FUNCTION__, nextSize);

		//instances = (tInstance *)_syslibRealloc( instances, nextSize );
	}
	else {
		DPRINTF("%s: All instances freed. Freeing instances pointer [TID #%d]\n",
			__FUNCTION__, _gettid());
		//_syslibFree(instances);
		instances = NULL;
		nInstances = 0;
	}

	DPRINTF("%s: Removed entry from instance list [count is %d, TID #%d]\n",
		__FUNCTION__, nInstances, _gettid() );

	_syslibDumpInstances(0);

	if (nInstances == 0) {
		_syslibFree(instances);
	}

	DPRINTF_CS("%s: About to leave critical section [TID #%d]\n", __FUNCTION__, _gettid() );
	_syslibCriticalSectionLeave();
	DPRINTF_CS("%s: Critical section left [TID #%d]\n", __FUNCTION__, _gettid() );

	return 0;
}

/**
 * Alter database connection string
 *
 * @param  id     internal instance entry ID
 * @param  dbconn connection string
 * @return errno value
 */
int _syslibEntryAlterDBConn(int id, char *dbconn)
{
	if (dbconn == instances[id].dbconn) {
		DPRINTF("%s: Value dbconn is the same so not changing anything\n", __FUNCTION__);
		return -EINVAL;
	}

	_syslibFree(instances[id].dbconn);
	instances[id].dbconn = NULL;
	if (dbconn != NULL)
		instances[id].dbconn = strdup(dbconn);

	DPRINTF("%s: Entry #%d = { 'changed': { 'dbconn': '%s' } }\n",
		__FUNCTION__, id, dbconn);
	return 0;
}

/**
 * Alter database connection string for thread ID
 *
 * @param  tid    thread ID
 * @param  dbconn connection string
 * @return errno value
 */
int _syslibEntryAlterDBConnTID(long tid, char *dbconn)
{
	int id = _syslibGetID(tid);

	if (id < 0) {
		DPRINTF("%s: No entry found for TID #%d\n", __FUNCTION__, tid);
		return -ENOENT;
	}

	return _syslibEntryAlterDBConn(id, dbconn);
}

/**
 * Alter database connection pointer
 *
 * @param  id        internal instance entry ID
 * @param  dbconnptr connection pointer
 * @return errno value
 */
int _syslibEntryAlterDBConnPtr(int id, void *dbconnptr)
{
	if (instances[id].dbconnptr == dbconnptr) {
		DPRINTF("%s: Value dbconnptr is the same so not changing anything\n", __FUNCTION__);
		return -EINVAL;
	}

	instances[id].dbconnptr = dbconnptr;

	DPRINTF("%s: Entry #%d = { 'changed': { 'dbconnptr': '%s' } }\n",
		__FUNCTION__, id, dbconnptr);
	return 0;
}

/**
 * Alter database connection pointer for thread ID
 *
 * @param  tid       thread ID
 * @param  dbconnptr connection pointer
 * @return errno value
 */
int _syslibEntryAlterDBConnPtrTID(long tid, void *dbconnptr)
{
	int id = _syslibGetID(tid);

	if (id < 0) {
		DPRINTF("%s: No entry found for TID #%d\n", __FUNCTION__, tid);
		return -ENOENT;
	}

	return _syslibEntryAlterDBConnPtr(id, dbconnptr);
}

/**
 * Alter initialization done flag
 *
 * @param  id        internal instance entry ID
 * @param  initdone  new initialization done flag
 * @return errno value
 */
int _syslibEntryAlterInitDone(int id, int initdone)
{
	instances[id].initdone = initdone;

	DPRINTF("%s: Entry #%d = { 'changed': { 'initdone': '%d' } }\n",
		__FUNCTION__, id, initdone);
	return 0;
}

/**
 * Alter initialization done flag for thread ID
 *
 * @param  tid       thread ID
 * @param  initdone  new initialization done flag
 * @return errno value
 */
int _syslibEntryAlterInitDoneTID(long tid, int initdone)
{
	int id = _syslibGetID(tid);

	if (id < 0) {
		DPRINTF("%s: No entry found for TID #%d\n", __FUNCTION__, tid);
		return -ENOENT;
	}

	return _syslibEntryAlterInitDone(id, initdone);
}

/**
 * Alter debug file name
 *
 * @param  id         internal instance entry ID
 * @param  debugFile  debug file name
 * @return errno value
 */
int _syslibEntryAlterDebugFile(int id, char *debugFile)
{
	instances[id].debugFile = (debugFile == NULL) ? NULL : strdup(debugFile);

	if (instances[id].debugFile == NULL)
		DPRINTF("%s: Entry #%d = { 'changed': { 'debugFile': '<null>' } }\n",
			 __FUNCTION__, id);
	else
		DPRINTF("%s: Entry #%d = { 'changed': { 'debugFile': '%s' } }\n",
			__FUNCTION__, id, debugFile);

	return 0;
}

/**
 * Alter debug file name for thread ID
 *
 * @param  tid        thread ID
 * @param  debugFile  debug file name
 * @return errno value
 */
int _syslibEntryAlterDebugFileTID(long tid, char *debugFile)
{
	int id = _syslibGetID(tid);

	if (id < 0) {
		DPRINTF("%s: No entry found for TID #%d\n", __FUNCTION__, tid);
		return -ENOENT;
	}

	return _syslibEntryAlterDebugFile(id, debugFile);
}

/**
 * Alter debug file flags
 *
 * @param  id         internal instance entry ID
 * @param  debugFlags new debug flags
 * @return errno value
 */
int _syslibEntryAlterDebugFlags(int id, int debugFlags)
{
	instances[id].debugFlags = debugFlags;

	DPRINTF("%s: Entry #%d = { 'changed': { 'debugFlags': '%d' } }\n",
		__FUNCTION__, id, debugFlags);
	return 0;
}

/**
 * Alter debug file flags for thread ID
 *
 * @param  tid        thread ID
 * @param  debugFlags new debug flags
 * @return errno value
 */
int _syslibEntryAlterDebugFlagsTID(long tid, int debugFlags)
{
	int id = _syslibGetID(tid);

	if (id < 0) {
		DPRINTF("%s: No entry found for TID #%d\n", __FUNCTION__, tid);
		return -ENOENT;
	}

	return _syslibEntryAlterDebugFlagsTID(id, debugFlags);
}

/**
 * Get internal instance structure ID for current thread
 *
 * @return internal instance structure ID
 */
int _syslibGetCurrent(void)
{
	return _syslibGetID( _gettid() );
}

/**
 * Set database connection string for current thread
 *
 * @param  dbconn  database connection string
 * @return None
 */
void _syslibSetDBConn(char *dbconn)
{
	DPRINTF_CS("%s: About to enter critical section [TID #%d]\n", __FUNCTION__, _gettid() );
	_syslibCriticalSectionEnter();
	DPRINTF_CS("%s: Critical section entered [TID #%d]\n", __FUNCTION__, _gettid() );

	DPRINTF("%s: Called with argument '%s'\n",
		__FUNCTION__, dbconn);

	int id = _syslibGetCurrent();
	if (id < 0) {
		DPRINTF("%s: Allocating new entry\n", __FUNCTION__);
		id = _syslibEntryAlloc(_gettid(), dbconn, NULL, 0, NULL, 0);
	}
	else {
		DPRINTF("%s: Altering already existing entry\n", __FUNCTION__);
		_syslibEntryAlterDBConn(id, dbconn);
	}

	DPRINTF_CS("%s: About to leave critical section [TID #%d]\n", __FUNCTION__, _gettid() );
	_syslibCriticalSectionLeave();
	DPRINTF_CS("%s: Critical section left [TID #%d]\n", __FUNCTION__, _gettid() );

	if (id >= 0)
		DPRINTF("%s: DBConn for ID #%d changed to '%s'\n",
			__FUNCTION__, id, dbconn);
	else
		DPRINTF("%s: DBConn for ID #%d set to '%s'\n",
			__FUNCTION__, id, dbconn);
}

/**
 * Get database connection string for current thread
 *
 * @return database connection string or NULL
 */
char *_syslibGetDBConn(void)
{
	char *ret = NULL;

	tInstance inst;

	DPRINTF_CS("%s: About to enter critical section [TID #%d]\n", __FUNCTION__, _gettid() );
	_syslibCriticalSectionEnter();
	DPRINTF_CS("%s: Critical section entered [TID #%d]\n", __FUNCTION__, _gettid() );

	int id = _syslibGetCurrent();
	if (id < 0)
		goto cleanup;

	inst = instances[id];

	DPRINTF("Dumping connection for TID #%d:\n", id);
	_syslibDumpInstance(-1, inst, 0);

	if (inst.dbconn != NULL)
		ret = strdup(inst.dbconn);

cleanup:
	DPRINTF_CS("%s: About to leave critical section [TID #%d]\n", __FUNCTION__, _gettid() );
	_syslibCriticalSectionLeave();
	DPRINTF_CS("%s: Critical section left [TID #%d]\n", __FUNCTION__, _gettid() );

	if (id >= 0)
		DPRINTF("%s: DBConn for ID #%d is '%s'\n",
			__FUNCTION__, id, ret);
	return ret;
}

/**
 * Set instance debug file name for current thread
 *
 * @param  debugFile  debug file name
 * @return None
 */
void _syslibSetDebugFile(char *debugFile)
{
	DPRINTF_CS("%s: About to enter critical section [TID #%d]\n", __FUNCTION__, _gettid());
	_syslibCriticalSectionEnter();
	DPRINTF_CS("%s: Critical section entered [TID #%d]\n", __FUNCTION__, _gettid() );

	DPRINTF("%s: Called with argument '%s'\n",
		__FUNCTION__, debugFile);

	int id = _syslibGetCurrent();
	if (id < 0)
		id = _syslibEntryAlloc(_gettid(), NULL, NULL, 0, debugFile, 0);
	else
		_syslibEntryAlterDebugFile(id, debugFile);

	DPRINTF_CS("%s: About to leave critical section [TID #%d]\n", __FUNCTION__, _gettid() );
	_syslibCriticalSectionLeave();
	DPRINTF_CS("%s: Critical section left [TID #%d]\n", __FUNCTION__, _gettid() );

	DPRINTF("%s: DebugFile for ID #%d changed to %s\n",
		__FUNCTION__, id, (void *)debugFile);
}

/**
 * Get instance debug file name for current thread
 *
 * @return debug file name or NULL for none
 */
char *_syslibGetDebugFile(void)
{
	char *ret = NULL;

	DPRINTF_CS("%s: About to enter critical section [TID #%d]\n", __FUNCTION__, _gettid() );
	_syslibCriticalSectionEnter();
	DPRINTF_CS("%s: Critical section entered [TID #%d]\n", __FUNCTION__, _gettid() );

	int id = _syslibGetCurrent();
	if (id < 0)
		goto cleanup;

	ret = instances[id].debugFile;
cleanup:
	DPRINTF_CS("%s: About to leave critical section [TID #%d]\n", __FUNCTION__, _gettid() );
	_syslibCriticalSectionLeave();
	DPRINTF_CS("%s: Critical section left [TID #%d]\n", __FUNCTION__, _gettid() );

	if (ret == NULL)
		DPRINTF("%s: No debugFile for ID #%d found\n",
			 __FUNCTION__, _gettid());
	else
		DPRINTF("%s: No debugFile for ID #%d is %p\n",
			__FUNCTION__, id, ret);
	return ret;
}

/**
 * Set database connection pointer for current thread
 *
 * @param  ptr   database connection pointer
 * @return None
 */
void _syslibSetDBConnPtr(PGconn *ptr)
{
	DPRINTF("%s: Updating pointer for TID %d to %p\n", __FUNCTION__, _gettid(), ptr);
	DPRINTF_CS("%s: About to enter critical section [TID #%d]\n", __FUNCTION__, _gettid());
	_syslibCriticalSectionEnter();

	DPRINTF_CS("%s: Critical section entered [TID #%d]\n", __FUNCTION__, _gettid() );

	if (ptr == NULL)
		DPRINTF("%s: Called with NULL pointer argument\n",
			__FUNCTION__);
	else
		DPRINTF("%s: Called with pointer argument 0x%p\n",
			__FUNCTION__, ptr);

	int id = _syslibGetCurrent();
	if (id < 0)
		id = _syslibEntryAlloc(_gettid(), NULL, (void *)ptr, 0, NULL, 0);
	else
		_syslibEntryAlterDBConnPtr(id, (void *)ptr);

	DPRINTF_CS("%s: About to leave critical section [TID #%d]\n", __FUNCTION__, _gettid() );
	_syslibCriticalSectionLeave();
	DPRINTF_CS("%s: Critical section left [TID #%d]\n", __FUNCTION__, _gettid() );

	DPRINTF("%s: DBConnPtr for ID #%d changed to %p\n",
		__FUNCTION__, id, (void *)ptr);
}

/**
 * Get database connection pointer for current thread
 *
 * @return database connection pointer or NULL for none
 */
PGconn *_syslibGetDBConnPtr(void)
{
	PGconn *ret = NULL;

	DPRINTF_CS("%s: About to enter critical section [TID #%d]\n", __FUNCTION__, _gettid() );
	_syslibCriticalSectionEnter();
	DPRINTF_CS("%s: Critical section entered [TID #%d]\n", __FUNCTION__, _gettid() );

	int id = _syslibGetCurrent();
	if (id < 0)
		goto cleanup;

	ret = (PGconn *)instances[id].dbconnptr;
cleanup:
	DPRINTF_CS("%s: About to leave critical section [TID #%d]\n", __FUNCTION__, _gettid() );
	_syslibCriticalSectionLeave();
	DPRINTF_CS("%s: Critical section left [TID #%d]\n", __FUNCTION__, _gettid() );

	if (ret == NULL)
		DPRINTF("%s: No DBConnPtr for ID #%d found\n",
			 __FUNCTION__, _gettid());
	else
		DPRINTF("%s: DBConnPtr for ID #%d is %p\n",
			__FUNCTION__, id, ret);
	return ret;
}

/**
 * Set initialization done flag for current thread
 *
 * @param  initdone  new initialization done flag value
 * @return None
 */
void _syslibSetInitDone(int initdone)
{
	DPRINTF_CS("%s: About to enter critical section [TID #%d]\n", __FUNCTION__, _gettid() );
	_syslibCriticalSectionEnter();
	DPRINTF_CS("%s: Critical section entered [TID #%d]\n", __FUNCTION__, _gettid() );

	DPRINTF("%s: Called with argument %d\n",
		__FUNCTION__, initdone);

	int id = _syslibGetCurrent();
	if (id < 0)
		id = _syslibEntryAlloc(_gettid(), NULL, NULL, initdone, NULL, 0);
	else
		_syslibEntryAlterInitDone(id, initdone);

	DPRINTF_CS("%s: About to leave critical section [TID #%d]\n", __FUNCTION__, _gettid() );
	_syslibCriticalSectionLeave();
	DPRINTF_CS("%s: Critical section left [TID #%d]\n", __FUNCTION__, _gettid() );

	DPRINTF("%s: InitDone for ID #%d changed to %d\n",
		__FUNCTION__, id, initdone);
}

/**
 * Get initialization done flag for current thread
 *
 * @return initialization done flag value
 */
int _syslibGetInitDone(void)
{
	int ret = 0;

	DPRINTF_CS("%s: About to enter critical section [TID #%d]\n", __FUNCTION__, _gettid() );
	_syslibCriticalSectionEnter();
	DPRINTF_CS("%s: Critical section entered [TID #%d]\n", __FUNCTION__, _gettid() );

	int id = _syslibGetCurrent();
	if (id < 0) {
		ret = 0;
		goto cleanup;
	}

	ret = instances[id].initdone;

	DPRINTF("%s: InitDone for ID #%d is %d\n",
		__FUNCTION__, id, ret);

cleanup:
	DPRINTF_CS("%s: About to leave critical section [TID #%d]\n", __FUNCTION__, _gettid() );
	_syslibCriticalSectionLeave();
	DPRINTF_CS("%s: Critical section left [TID #%d]\n", __FUNCTION__, _gettid() );

	return ret;
}

/**
 * Set debug flags for current thread
 *
 * @param  debugFlags  new debug flags
 * @return None
 */
void _syslibSetDebugFlags(int debugFlags)
{
	DPRINTF_CS("%s: About to enter critical section [TID #%d]\n", __FUNCTION__, _gettid() );
	_syslibCriticalSectionEnter();
	DPRINTF_CS("%s: Critical section entered [TID #%d]\n", __FUNCTION__, _gettid() );

	DPRINTF("%s: Called with argument %d\n",
		__FUNCTION__, debugFlags);

	int id = _syslibGetCurrent();
	if (id < 0)
		id = _syslibEntryAlloc(_gettid(), NULL, NULL, 0, NULL, debugFlags);
	else
		_syslibEntryAlterDebugFlags(id, debugFlags);

	DPRINTF_CS("%s: About to leave critical section [TID #%d]\n", __FUNCTION__, _gettid() );
	_syslibCriticalSectionLeave();
	DPRINTF_CS("%s: Critical section left [TID #%d]\n", __FUNCTION__, _gettid() );

	DPRINTF("%s: Debug flags for ID #%d changed to %d\n",
		__FUNCTION__, id, debugFlags);
}

/**
 * Get debug flags for current thread
 *
 * @return debug flags
 */
int _syslibGetDebugFlags(void)
{
	int ret = 0;

	DPRINTF_CS("%s: About to enter critical section [TID #%d]\n", __FUNCTION__, _gettid() );
	_syslibCriticalSectionEnter();
	DPRINTF_CS("%s: Critical section entered [TID #%d]\n", __FUNCTION__, _gettid() );

	int id = _syslibGetCurrent();
	if (id < 0) {
		ret = 0;
		goto cleanup;
	}

	ret = instances[id].debugFlags;

	DPRINTF("%s: Debug flags for ID #%d is %d\n",
		__FUNCTION__, id, ret);

cleanup:
	DPRINTF_CS("%s: About to leave critical section [TID #%d]\n", __FUNCTION__, _gettid() );
	_syslibCriticalSectionLeave();
	DPRINTF_CS("%s: Critical section left [TID #%d]\n", __FUNCTION__, _gettid() );

	return ret;
}

/**
 * Generate system UUID string
 *
 * @return generated system UUID string
 */
char *_syslibSystemUUID(void)
{
	char uuid[128] = { 0 };
	char cmd[1024] = { 0 };
	FILE *fp = NULL;
	int uid;

	uid = setuid(0);
	snprintf(cmd, sizeof(cmd), "dmidecode 2> /dev/null | grep UUID | awk '{split($0, a, \": \"); print a[2]}'");

	fp = popen(cmd, "r");
	if (fp == NULL) {
		setuid(uid);
		logWrite(LOG_LEVEL_DEBUG, "%s: Cannot read machine ID from system.\n", __FUNCTION__);
		return NULL;
	}

	fgets(uuid, sizeof(uuid), fp);
	fclose(fp);
	setuid(uid);

	if (strnlen(uuid, sizeof(uuid)) > 0)
                uuid[strnlen(uuid, sizeof(uuid)) - 1] = 0;
	if (strnlen(uuid, sizeof(uuid)) == 0) {
		logWrite(LOG_LEVEL_DEBUG, "%s: Cannot read machine ID from system.\n", __FUNCTION__);
		return NULL;
	}

	snprintf(cmd, sizeof(cmd), "echo \"%s\" | md5sum | awk '{split($0, a, \" \"); print a[1]}'", uuid);

	fp = popen(cmd, "r");
	if (fp == NULL) {
		logWrite(LOG_LEVEL_DEBUG, "%s: Cannot read machine ID from system.\n", __FUNCTION__);
		return NULL;
	}

	fgets(uuid, sizeof(uuid), fp);
	fclose(fp);

	if (strnlen(uuid, sizeof(uuid)) > 0)
		uuid[strnlen(uuid, sizeof(uuid)) - 1] = 0;
	else {
		logWrite(LOG_LEVEL_DEBUG, "%s: Cannot read machine ID from system.\n", __FUNCTION__);
		return NULL;
	}

	logWrite(LOG_LEVEL_DEBUG, "%s: Machine ID read from system successfully.\n", __FUNCTION__);
	return strdup(uuid);
}

/**
 * Get system UUID string
 *
 * @return system UUID string
 */
char *syslibSystemUUID(void)
{
	char buf[64] = { 0 };

	FILE *fp = fopen(MACHINE_UUID_FILE, "r");
	if (fp == NULL) {
		char *ret = NULL;
		logWrite(LOG_LEVEL_DEBUG, "%s: Cannot read machine ID file. Accessing system information ...\n", __FUNCTION__);
		ret = _syslibSystemUUID();

		FILE *fp = fopen(MACHINE_UUID_FILE, "w");
		if (fp != NULL) {
			fprintf(fp, "%s", ret);
			fclose(fp);
		}
		return ret;
	}

	fgets(buf, sizeof(buf), fp);
	fclose(fp);

	if (strnlen(buf, sizeof(buf)) > 0)
		buf[strnlen(buf, sizeof(buf)) - 1] = 0;

	logWrite(LOG_LEVEL_DEBUG, "%s: Got machine UUID '%s'\n", __FUNCTION__, buf);
	return strdup(buf);
}

/**
 * Get AES encrypted string by UUID
 *
 * @param  str  original string
 * @param  useAES256 flag whether to use better encryption (AES-256) or standard AES-128
 * @return encrypted string in base64 form, $9$ prefixed
 */
char *syslibAESEncrypt(char *str, int useAES256)
{
	char ret[4096] = { 0 };
	char *tmp = NULL;

	if (str == NULL)
		return NULL;

	tmp = aesEncryptData(str, NULL, 0, useAES256);

	if (tmp == NULL) {
		logWrite(LOG_LEVEL_ERROR, "Machine specific encryption failed\n");
		return NULL;
	}

	if (useAES256)
		snprintf(ret, sizeof(ret), "$A$%s", tmp);
	else
		snprintf(ret, sizeof(ret), "$9$%s", tmp);
	free(tmp);

	logWrite(LOG_LEVEL_DEBUG, "Machine specific encryption for string '%s' returned '%s'\n",
		str, ret);
	return strdup(ret);
}

/**
 * Decrypt and get AES string ($9$ prefixed) by UUID
 *
 * @param  str  original string
 * @return decrypted string
 */
char *syslibAESDecrypt(char *str)
{
	if (str == NULL)
		return NULL;
	char *ret = aesDecryptData(str + 3, NULL, 0, (str[1] == 'A') ? 1 : 0);
	if (ret == NULL)
		logWrite(LOG_LEVEL_ERROR, "Machine specific decryption failed\n");
	else
		logWrite(LOG_LEVEL_DEBUG, "Machine specific decryption for string '%s' returned '%s'\n",
			str, ret);
	return ret;
}

/**
 * Get connection string
 *
 * @param key configuration entry key
 * @return connection string
 */
char *syslibGetConnectionString(char *key)
{
	char *ret = NULL;

	_syslibCriticalSectionEnter();
	char *k = confGet(key);
	_syslibCriticalSectionLeave();

	#ifdef ENABLE_CONF_DUMP
	confDump();
	#endif

	if (k == NULL)
		return NULL;

	if (strncmp(k, "$9$", 3) == 0)
		ret = aesDecryptData(k + 3, NULL, 0, (k[1] == 'A') ? 1 : 0);
	else
		ret = strdup(k);

	return ret;
}

/**
 * Get partition information
 *
 * @param path  partition path
 * @param size  output long for total size
 * @param free  output long for free space
 * @param used  output long for used space
 * @return partition usage in percent
 */
int syslibGetPartitionInfo(char *path, unsigned long *size, unsigned long *free, unsigned long *used)
{
        unsigned long ret = 0;
        struct statfs fs;

        if (statfs(path, &fs) != 0)
                return -EINVAL;

        if (size != NULL)
                *size = fs.f_bsize * fs.f_blocks;
        if (free != NULL)
                *free = fs.f_bsize * fs.f_bavail;
        if (used != NULL)
                *used = (fs.f_blocks - fs.f_bfree) * fs.f_bsize;

        return ((int)(((fs.f_blocks - fs.f_bfree) * fs.f_bsize) / ((fs.f_bsize * fs.f_blocks) / 100.))) + 1;
}

/**
 * Get partition list
 *
 * @param num   output value of partition entries
 * @return string array of partitions
 */
char **syslibGetPartitionList(int *num)
{
	FILE *aFile;
	struct mntent *ent;
	char **partitions = NULL;

	aFile = setmntent("/proc/mounts", "r");
	if (aFile == NULL)
		return NULL;

	partitions = (char **)malloc( sizeof(char *) );

	int i = 0;
	while ((ent = getmntent(aFile)) != NULL) {
		partitions = (char **)realloc( partitions, ( i + 1) * sizeof(char *) );
		partitions[i] = strdup(ent->mnt_dir);

		i++;
	}

	if (num != NULL)
		*num = i;

	endmntent(aFile);
	return partitions;
}

/**
 * Get ring sizes for device
 *
 * @param dev     device identifier
 * @param oring   ring parameter structure
 * @return errno return value
 */
int syslibInterfaceGetRingSize(char *dev, struct ethtool_ringparam *oring)
{       
	int err, ret = 0;
	struct ifreq ifr;
	struct ethtool_ringparam ering = { 0 };

	ering.cmd = ETHTOOL_GRINGPARAM;

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, dev);

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_data = (void *)&ering;
	err = ioctl(fd, SIOCETHTOOL, &ifr);
	if (err == 0) {
		if (oring != NULL)
			*oring = ering;
	} else
		ret = -22;
	close(fd);

	return ret;
}

/**
 * Get ring RX sizes for device
 *
 * @param dev      device identifier
 * @param rx       output rx value
 * @param rx_mini  output rx_mini value
 * @param rx_jumbo output rx_jumbo value
 * @return errno return value
 */
int syslibInterfaceGetRxRingSize(char *dev, int *rx, int *rx_mini, int *rx_jumbo)
{
	int err, ret = 0;
	struct ifreq ifr;
	struct ethtool_ringparam ering = { 0 };

	ering.cmd = ETHTOOL_GRINGPARAM;

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, dev);

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_data = (void *)&ering;
        err = ioctl(fd, SIOCETHTOOL, &ifr);
        if (err == 0) {
		if (rx != NULL)
			*rx = ering.rx_max_pending;
		if (rx_mini != NULL)
			*rx_mini = ering.rx_mini_max_pending;
		if (rx_jumbo != NULL)
			*rx_jumbo = ering.rx_jumbo_max_pending;
        } else
		ret = -22;
	close(fd);

        return ret;
}

/**
 * Set ring RX size for device
 *
 * @param dev      device identifier
 * @param val      new rx value
 * @return errno return value
 */
int syslibInterfaceSetRxRingSize(char *dev, int val)
{
	int err, ret = 0;
	struct ifreq ifr;
	struct ethtool_ringparam ering;

	ering.cmd = ETHTOOL_GRINGPARAM;

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, dev);

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_data = (void *)&ering;
        err = ioctl(fd, SIOCETHTOOL, &ifr);
        if (err == 0) {
		ering.rx_pending = (val > 0) ? val : ering.rx_max_pending;
		ering.rx_mini_pending = (val > 0) ? val : ering.rx_mini_max_pending;
		ering.rx_jumbo_max_pending = (val > 0) ? val : ering.rx_jumbo_pending;

		ering.cmd = ETHTOOL_SRINGPARAM;
		ifr.ifr_data = (void *)&ering;
		err = ioctl(fd, SIOCETHTOOL, &ifr);
		if (err)
			ret = -2;
        } else
                ret = -22;
	close(fd);

        return ret;
}

/**
 * Get device driver for interface/device
 *
 * @param dev      device identifier
 * @return driver string
 */
char *syslibInterfaceGetDriver(char *dev)
{
	int err;
	char *ret = NULL;
	struct ifreq ifr;
	struct ethtool_drvinfo drvinfo;

	drvinfo.cmd = ETHTOOL_GDRVINFO;

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, dev);

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_data = (void *)&drvinfo;
	err = ioctl(fd, SIOCETHTOOL, &ifr);
	if ((err == 0) && (drvinfo.driver != NULL) && (strnlen(drvinfo.driver, 10) > 0))
		ret = strdup(drvinfo.driver);
	else
		ret = NULL;
        close(fd);

	return ret;
}

/**
 * Get device driver version for interface/device
 *
 * @param dev      device identifier
 * @return driver version string
 */
char *syslibInterfaceGetDriverVersion(char *dev)
{
	int err;
	char *ret = NULL;
	struct ifreq ifr;
	struct ethtool_drvinfo drvinfo;

	drvinfo.cmd = ETHTOOL_GDRVINFO;

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, dev);

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_data = (void *)&drvinfo;
	err = ioctl(fd, SIOCETHTOOL, &ifr);
	if ((err == 0) && (drvinfo.version != NULL) && (strnlen(drvinfo.version, 10) > 0))
		ret = strdup(drvinfo.version);
	else
		ret = NULL;
	close(fd);

	return ret;
}

/**
 * Get device driver bus information for interface/device
 *
 * @param dev      device identifier
 * @return driver bus information string
 */
char *syslibInterfaceGetDriverBusInfo(char *dev)
{
	int err;
	char *ret = NULL;
	struct ifreq ifr;
	struct ethtool_drvinfo drvinfo;

	drvinfo.cmd = ETHTOOL_GDRVINFO;

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, dev);

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_data = (void *)&drvinfo;
	err = ioctl(fd, SIOCETHTOOL, &ifr);
	if ((err == 0) && (drvinfo.bus_info != NULL) && (strnlen(drvinfo.bus_info, 10) > 0))
		ret = strdup(drvinfo.bus_info);
	else
		ret = NULL;
	close(fd);

	return ret;
}

/**
 * Get device driver firmware version information for interface/device
 *
 * @param dev      device identifier
 * @return driver firmware version information string
 */
char *syslibInterfaceGetDriverFWVersion(char *dev)
{
	int err;
	char *ret = NULL;
	struct ifreq ifr;
	struct ethtool_drvinfo drvinfo;

	drvinfo.cmd = ETHTOOL_GDRVINFO;

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, dev);

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_data = (void *)&drvinfo;
	err = ioctl(fd, SIOCETHTOOL, &ifr);
	if ((err == 0) && (drvinfo.fw_version != NULL) && (strnlen(drvinfo.fw_version, 10) > 0))
		ret = strdup(drvinfo.fw_version);
	else
		ret = NULL;
	close(fd);

	return ret;
}

/**
 * Check whether interface/device has flag set
 *
 * @param dev      device identifier
 * @param flag     flag identifier
 * @return boolean
 */
int syslibInterfaceGetFlag(char *dev, int flag)
{       
	int err, ret = 0;
	struct ifreq ifr;
	struct ethtool_value eval;

	eval.cmd = 0;
	if (flag & IF_RXCS)
		eval.cmd = ETHTOOL_GRXCSUM;
	if (flag & IF_TXCS)
		eval.cmd = ETHTOOL_GTXCSUM;
	if (flag & IF_SG)
		eval.cmd = ETHTOOL_GSG;
	if (flag & IF_TSO)
		eval.cmd = ETHTOOL_GTSO;
	if (flag & IF_UFO)
		eval.cmd = ETHTOOL_GUFO;
	if (flag & IF_GSO)
		eval.cmd = ETHTOOL_GGSO;
	if (flag & IF_GRO)
		eval.cmd = ETHTOOL_GGRO;
	// Following commands are not supported by kernel interface
	// See: http://lxr.free-electrons.com/source/include/uapi/linux/ethtool.h
	if (flag & IF_LRO)
		eval.cmd = 0;
	if (flag & IF_RXVLAN)
		eval.cmd = 0;
	if (flag & IF_TXVLAN)
		eval.cmd = 0;
	if (flag & IF_RXHASH)
		eval.cmd = 0;

	if (eval.cmd == 0)
		return -22;

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, dev);

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_data = (void *)&eval;
	err = ioctl(fd, SIOCETHTOOL, &ifr);
	if (err == 0)
		ret = eval.data;
	else
		ret = -22;
	close(fd);

	return ret;
}

/**
 * Set interface/device flag
 *
 * @param dev      device identifier
 * @param flag     flag identifier
 * @param val      boolean value = 0 - false, 1 - true
 * @return errno return code
 */
int syslibInterfaceSetFlag(char *dev, int flag, int val)
{       
	int err, ret = 0;
	struct ifreq ifr;
	struct ethtool_value eval;

        eval.cmd = 0;
        if (flag & IF_RXCS)
                eval.cmd = ETHTOOL_SRXCSUM;
        if (flag & IF_TXCS)
                eval.cmd = ETHTOOL_STXCSUM;
        if (flag & IF_SG)
                eval.cmd = ETHTOOL_SSG;
        if (flag & IF_TSO)
                eval.cmd = ETHTOOL_STSO;
        if (flag & IF_UFO)
                eval.cmd = ETHTOOL_SUFO;
        if (flag & IF_GSO)
                eval.cmd = ETHTOOL_SGSO;
        if (flag & IF_GRO)
                eval.cmd = ETHTOOL_SGRO;
	// Following commands are not supported by kernel interface
	// See: http://lxr.free-electrons.com/source/include/uapi/linux/ethtool.h
        if (flag & IF_LRO)
                eval.cmd = 0;
        if (flag & IF_RXVLAN)
                eval.cmd = 0;
        if (flag & IF_TXVLAN)
                eval.cmd = 0;
        if (flag & IF_RXHASH)
                eval.cmd = 0;

	if (eval.cmd == 0)
		return -22;

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, dev);

	eval.data = (val == 0) ? 0 : 1;

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_data = (void *)&eval;
	err = ioctl(fd, SIOCETHTOOL, &ifr);
	if (err != 0)
		ret = -22;
	close(fd);

	return ret;
}

/**
 * Get interface/device MAC address
 * 
 * @param dev      device identifier
 * @return MAC address string
 */
char *syslibInterfaceGetMACAddress(char *dev)
{
	return getMACAddress(dev);
}

/**
 * Get interface/device MTU value
 *
 * @param dev      device identifier
 * @return MTU value
 */
int syslibInterfaceGetMTU(char *dev)
{       
	int err, ret = 0;
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, dev);

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	err = ioctl(fd, SIOCGIFMTU, &ifr);
	ret = (err == 0) ? ifr.ifr_mtu : -22;
	close(fd);

	return ret;
}

/**
 * Set interface/device MTU value
 *
 * @param dev      device identifier
 * @param mtu      MTU value
 * @return errno return value
 */
int syslibInterfaceSetMTU(char *dev, int mtu)
{       
	int err, ret = 0;
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, dev);

	ifr.ifr_mtu = mtu;

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	err = ioctl(fd, SIOCSIFMTU, &ifr);
	if (err != 0)
		ret = -22;
	close(fd);

	return ret;
}

/**
 * Get interface/device promiscuous mode settings
 *
 * @param dev      device identifier
 * @return boolean
 */
int syslibInterfaceGetPromisc(char *dev)
{
	int err, ret = 0;
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, dev);

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
		close(fd);
		return -22;
	}
	close(fd);

	return (ifr.ifr_flags & IFF_PROMISC) ? 1 : 0;
}

/**
 * Set interface/device promiscuous mode settings
 *
 * @param dev      device identifier
 * @param val      promiscuous mode settings => 0 - disable, 1 - enable
 * @return boolean
 */
int syslibInterfaceSetPromisc(char *dev, int val)
{
	int err, ret = 0;
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, dev);

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
		close(fd);
		return -22;
	}

	if (val == 0)
		ifr.ifr_flags &= ~IFF_PROMISC;
	else
		ifr.ifr_flags |= IFF_PROMISC;

	err = ioctl(fd, SIOCSIFFLAGS, &ifr);
	if (err != 0)
		ret = -22;
	close(fd);

	return ret;
}

/**
 * Get kernel's sysctl variable
 *
 * @param var      kernel variable
 * @return value
 */
long syslibSysctlGet(char *var)
{
	int i;
	char tmp[1024] = { 0 };

	if (var == NULL)
		return -22;

	snprintf(tmp, sizeof(tmp), "/proc/sys/%s", var);

	for (i = 0; i < strlen(tmp); i++)
		if (tmp[i] == '.')
			tmp[i] = '/';

	int fd = open(tmp, O_RDONLY);
	if (fd < 0)
		return -2;

	memset(tmp, 0, sizeof(tmp));
	read(fd, tmp, sizeof(tmp));
	close(fd);

	return atol(tmp);
}

/**
 * Set kernel's sysctl variable
 *
 * @param var      kernel variable
 * @param value    new value
 * @return errno return value
 */
int syslibSysctlSet(char *var, long value)
{
	int i;
	char tmp[1024] = { 0 };

	if (var == NULL)
		return -22;

	snprintf(tmp, sizeof(tmp), "/proc/sys/%s", var);

	for (i = 0; i < strlen(tmp); i++)
		if (tmp[i] == '.')
			tmp[i] = '/';

	int fd = open(tmp, O_WRONLY|O_CREAT|O_TRUNC, 0666);
	if (fd < 0)
		return -2;

	memset(tmp, 0, sizeof(tmp));
	snprintf(tmp, sizeof(tmp), "%ld\n", value);
	write(fd, tmp, strlen(tmp));
	close(fd);

	return 0;
}

/**
 * Internal function to find process by it's iNode number
 *
 * @param inode    inode number
 * @return resulting PID or 0 for no process found
 */
int _findProcessByINode(int inode)
{
	int ret = 0;
	char buf[4096] = { 0 };
	char exps[128] = { 0 };
        DIR *dir = opendir("/proc");
        struct dirent *pent = NULL;

	snprintf(exps, sizeof(exps), "socket:[%d]", inode);

        if (dir == NULL)
                return 0;
        while (pent = readdir(dir)) {
                if (pent != NULL) {
                        if (strncmp(pent->d_name, ".", 1) != 0) {
				char tmp[1024] = { 0 };

				snprintf(tmp, sizeof(tmp), "/proc/%s/fd", pent->d_name);

				DIR *dir2 = opendir(tmp);
				struct dirent *pent2 = NULL;
				if (dir2 != NULL) {
					while (pent2 = readdir(dir2)) {
						if (pent2 != NULL) {
							if (strncmp(pent2->d_name, ".", 1) != 0) {
								snprintf(tmp, sizeof(tmp), "/proc/%s/fd/%s", pent->d_name, pent2->d_name);

								memset(buf, 0, sizeof(buf));
								readlink(tmp, buf, sizeof(buf));

								if (strcmp(buf, exps) == 0)
									ret = atoi(pent->d_name);
							}
						}
					}
				}
				closedir(dir2);
                        }
                }
        }
        closedir(dir);

	return ret;
}

/**
 * Get process ID by open socket/port
 *
 * @param port    port number
 * @return resulting PID or 0 for no process found
 */
int syslibGetProcessIDByPort(int port)
{
	int ret = 0;
	unsigned long rxq, txq, time_len, retr, inode;
	int num, local_port, rem_port, d, state, uid, timer_run, timeout;
	char rem_addr[128], local_addr[128], timers[64], buffer[1024], more[512];
	struct aftype *ap;
	struct sockaddr_in localaddr, remaddr;

	char buf[1024] = { 0 };
	FILE *fp = fopen("/proc/net/tcp", "r");

	if (fp == NULL)
		return -2;

	state = 0;
	while (!feof(fp)) {
		memset(buf, 0, sizeof(buf));
		fgets(buf, sizeof(buf), fp);

		if ((strlen(buf) > 0) && (buf[strlen(buf) - 1] == '\n'))
			buf[strlen(buf) - 1] = 0;

		num = sscanf(buf,
			"%d: %64[0-9A-Fa-f]:%X %64[0-9A-Fa-f]:%X %X %lX:%lX %X:%lX %lX %d %d %ld %512s\n",
			 &d, local_addr, &local_port, rem_addr, &rem_port, &state,
			 &txq, &rxq, &timer_run, &time_len, &retr, &uid, &timeout, &inode, more);

		if ((state == TCP_LISTEN) && ((local_port == port) || (rem_port == port)))
		{
			ret = _findProcessByINode(inode);
			break;
		}
	}
	fclose(fp);

	return ret;
}

/**
 * Get process name by it's process ID
 *
 * @param pid    process ID
 * @return process name string
 */
char *syslibGetProcessNameByPID(int pid)
{
	char tmp[1024] = { 0 };
	char buf[1024] = { 0 };

        snprintf(tmp, sizeof(tmp), "/proc/%d/exe", pid);

	if (readlink(tmp, buf, sizeof(buf)) < 0)
		return NULL;

	return strdup(basename(buf));
}

/**
 * Run a select query on active database connection
 *
 * @param table      table to run query on
 * @param numVars    number of variables in vars argument
 * @param vars       variables/fields to read from database
 * @param condition  condition to append to the end of the query before execution
 * @return query result structure
 */
tQueryResult syslibQuerySelect(char *table, int numVars, char **vars, char *condition)
{
	int i;
	tQueryResult ret;
	char query[8192] = { 0 };

	ret.nRows = 0;
	ret.rows = NULL;

	snprintf(query, sizeof(query), "SELECT ");

	for (i = 0; i < numVars; i++) {
		strncat(query, vars[i], sizeof(query));
		if (i < numVars - 1)
			strncat(query, ", ", sizeof(query));
	}

	strncat(query, " FROM ", sizeof(query));

	strncat(query, table, sizeof(query));

	if (condition != NULL) {
		strncat(query, " ", sizeof(query));
		strncat(query, condition, sizeof(query));
	}

	strncat(query, ";", sizeof(query));

	ret = pqSelectAdvanced(query, numVars, vars);
	DPRINTF("%s: Query '%s' returned '%s' [TID #%d]\n",
		__FUNCTION__, query, ret, _gettid());
	logWrite(LOG_LEVEL_DEBUG, "%s: Query '%s' returned '%s' [TID #%d]\n",
		__FUNCTION__, query, ret, _gettid());

	return ret;
}

/**
 * Dump a query result
 *
 * @param res        query result
 * @return query result value
 */
int syslibQueryResultDump(tQueryResult res)
{
	int i, j, k;

	if (res.nRows == 0)
		return -EINVAL;

	printf("------------------------------------\n");
	printf("Row count: %d\n", res.nRows);
	printf("------------------------------------\n");
	for (i = 0; i < res.nRows; i++) {
		printf("Row #%d (%d field(s)):\n", i, res.rows[i].nFields);

		for (j = 0; j < res.rows[i].nFields; j++) {
			printf("\tField #%d:\n", j);
			printf("\t\tName: %s\n", res.rows[i].fields[j].name);
			if (res.rows[i].fields[j].val == NULL)
				printf("\t\tValue: <null>\n");
			else
				printf("\t\tValue: %s\n", res.rows[i].fields[j].val);

			if (res.rows[i].fields[j].nParsedVals > 0) {
				printf("\t\tisArray: true\n");
				for (k = 0; k < res.rows[i].fields[j].nParsedVals; k++) {
					printf("\t\t\tArray value #%d: %s\n", k, res.rows[i].fields[j].parsedVals[k]);
				}
			}
			else
				printf("\t\tisArray: false\n");
		}
		printf("------------------------------------\n");
	}

	return 0;
}

/**
 * Free a query result
 *
 * @param res        query result
 * @return errno return value
 */
int syslibQueryResultFree(tQueryResult res)
{
	int i, j, k;

	if (res.nRows == 0)
		return -EINVAL;

	for (i = 0; i < res.nRows; i++) {
		for (j = 0; j < res.rows[i].nFields; j++) {
			if (res.rows[i].fields[j].nParsedVals > 0) {
				for (k = 0; k < res.rows[i].fields[j].nParsedVals; k++)
					free(res.rows[i].fields[j].parsedVals[k]);
			}
			free(res.rows[i].fields[j].name);
			free(res.rows[i].fields[j].val);
		}
		free(res.rows[i].fields);
	}

	return 0;
}

int syslibQueryExecute(char *query, char *connstr)
{
	if (connstr != NULL) {
		if (strncmp(connstr, "postgresql://", 13) == 0) {
			if (_hasPQLib == 0) {
				if (syslibPQInit() != 0)
					return -ENOTSUP;
			}

			printf("GID: %d\n", _syslibGetInitDone());
			if (_syslibGetInitDone() == 0) {
				printf("Connecting to %s\n", connstr);
				if (pqConnect(connstr, NULL) != 0) {
					pqCleanup();
					libLogToFile(LOG_ERROR, "%s: Connection to database failed\n", __FUNCTION__);
					return -EINVAL;
				}
			}

			return pqExecute(query);
		}

		return 0;
	}

	return pqExecute(query);
}

/**
 * Insert entry to database using active database connection
 *
 * @param table      table to run query on
 * @param numVars    number of variables in vars argument
 * @param vars       variables/fields to read from database
 * @param vals       values for all variables/fields (sizeof(vals) have to be the same as sizeof(vars))
 * @return query result value
 */
int syslibQueryInsert(char *table, int numVars, char **vars, char **vals)
{
	int i;
	char query[8192] = { 0 };

	snprintf(query, sizeof(query), "INSERT INTO %s(", table);

	for (i = 0; i < numVars; i++) {
		strncat(query, vars[i], sizeof(query));
		if (i < numVars - 1)
			strncat(query, ", ", sizeof(query));
	}

	strncat(query, ") VALUES (", sizeof(query));

	for (i = 0; i < numVars; i++) {
		int noEscape = 0;
		if (strncmp(vals[i], "NOW()", 5) == 0)
			noEscape = 1;

		if (noEscape == 0)
			strncat(query, "'", sizeof(query));
		strncat(query, vals[i], sizeof(query));
		if (noEscape == 0)
			strncat(query, "'", sizeof(query));

		if (i < numVars - 1)
			strncat(query, ", ", sizeof(query));
	}

	strncat(query, ");", sizeof(query));

	int rc = pqExecute(query);
        DPRINTF("%s: Query '%s' returned %d [TID #%d]\n",
                __FUNCTION__, query, rc, _gettid());
	logWrite(LOG_LEVEL_DEBUG, "%s: Query '%s' returned %d [TID #%d]\n",
		__FUNCTION__, query, rc, _gettid());

	return rc;
}

/**
 * Do a debug dump of all instances
 *
 * @return None
 */
void syslibDebugDump(void)
{
	_syslibDumpInstances(1);
}

/**
 * Read a single entry from database
 *
 * @param  table            table to run query on
 * @param  field            field to read from database
 * @param  sensor           sensor to read value for
 * @param  conditionAppend  condition to append to generated condition
 * @param  def              default value
 * @return read value or default if not found
 */
char *syslibQueryGetSingle(char *table, char *field, char *sensor, char *conditionAppend, char *def)
{
	char query[4096] = { 0 };
	char *ret = NULL;

	if (conditionAppend == NULL)
		snprintf(query, sizeof(query), "SELECT %s as val FROM %s WHERE sensor = '%s'",
			field, table, sensor);
	else {
		if (strncmp(conditionAppend, "WHERE ", 6) == 0)
			snprintf(query, sizeof(query), "SELECT %s as val FROM %s %s",
				field, table, conditionAppend);
		else
			snprintf(query, sizeof(query), "SELECT %s as val FROM %s WHERE sensor = '%s' AND %s",
				field, table, sensor, conditionAppend);
	}

	ret = pqSelect(query, "val");
	DPRINTF("%s: Query '%s' returned '%s' [TID #%d]\n",
		__FUNCTION__, query, ret, _gettid());
	logWrite(LOG_LEVEL_DEBUG, "%s: Query '%s' returned '%s' [TID #%d]\n",
		__FUNCTION__, query, ret, _gettid());

	return (ret != NULL) ? ret : def;
}

/**
 * Read entire array from database
 *
 * @param  table            table to run query on
 * @param  field            field to read from database
 * @param  out              number of output fields
 * @param  sensor           sensor to read values for
 * @param  conditionAppend  condition to append to generated condition
 * @return string array for read strings
 */
char **syslibQueryGetArray(char *table, char *field, int *out, char *sensor, char *conditionAppend)
{
	char query[4096] = { 0 };
	char **retval = NULL;
	char *ret = NULL;
	tTokenizer tmp;

	if (conditionAppend == NULL)
		snprintf(query, sizeof(query), "SELECT %s as val FROM %s WHERE sensor = '%s'",
			field, table, sensor);
	else
		snprintf(query, sizeof(query), "SELECT %s as val FROM %s WHERE sensor = '%s' AND %s",
			field, table, sensor, conditionAppend);

	ret = pqSelect(query, "val");
	if (ret == NULL)
		return retval;

	if ((strlen(ret) < 1) || (ret[0] != '{') || (ret[strlen(ret) - 1] != '}'))
		return retval;

	*ret++;
	ret[strlen(ret) - 1] = 0;

	tmp = tokenize(ret, ",");

	int i, j = 0;
	retval = (char **)malloc( tmp.numTokens * sizeof(char *) );
	for (i = 0; i < tmp.numTokens; i++) {
		retval[i] = strdup(tmp.tokens[i]);
		j++;
	}
	tokensFree(tmp);

	if (out != NULL)
		*out = j;

	DPRINTF("%s: Query '%s' returned '%s' [TID #%d]\n",
		__FUNCTION__, query, ret, _gettid());
	logWrite(LOG_LEVEL_DEBUG, "%s: Query '%s' returned '%s' [TID #%d]\n",
		__FUNCTION__, query, ret, _gettid());

	return retval;
}

/**
 * Get short hostname
 *
 * @return short hostname
 */
char *syslibGetShortHostName(void)
{
	int i;
	char buf[1024] = { 0 };

	if (gethostname(buf, sizeof(buf)) != 0)
		return NULL;

	for (i = 0; i < strnlen(buf, sizeof(buf)); i++)
		if (buf[i] == '.') {
			buf[i] = 0;
			break;
		}

	return strdup(buf);
}

/**
 * Set environment variable
 *
 * @param  name    environment variable name
 * @param  val     new environment variable value
 * @return errno result value
 */
int syslibEnvSet(char *name, char *val)
{
	if (val == NULL)
		return unsetenv(name);
	else
		return setenv(name, val, 1);
}

/**
 * Get environment variable
 *
 * @param  name    environment variable name
 * @return environment variable value
 */
char *syslibEnvGet(char *name)
{
	return getenv(name);
}

/**
 * Ensure UUID file exists
 *
 * @return errno return code
 */
int syslibEnsureUUIDFile(void)
{
	if (access(MACHINE_UUID_FILE, F_OK) == 0)
		return 0;

	FILE *fp = fopen(MACHINE_UUID_FILE, "w");
	if (fp == NULL)
		return -EPERM;

	char *uuid = _syslibSystemUUID();
	if (uuid == NULL)
		return -ENOTSUP;

	fprintf(fp, "%s", uuid);
	fclose(fp);

	free(uuid);
	return 0;
}

/**
 * Convert database timestamp to unix timestamp
 *
 * @param  ts    timestamp in SQL format
 * @return timestamp in UNIX format
 */
unsigned int syslibConvertTimestampToUnix(char *ts)
{
	unsigned int rv = 0;
	char query[1024] = { 0 };
	char *ret = NULL;

	snprintf(query, sizeof(query), "SELECT round(date_part('epoch', '%s'::timestamp)) as val;",
		ts);

	ret = pqSelect(query, "val");
	if (ret == NULL)
		return 1;

	rv = atoi(ret);
	logWrite(LOG_LEVEL_DEBUG, "%s: Query '%s' returned '%s' [%d] [TID #%d]\n",
		__FUNCTION__, query, ret, rv, _gettid());
	DPRINTF("%s: Query '%s' returned '%s' [%d] [TID #%d]\n",
		__FUNCTION__, query, ret, rv, _gettid());

	return rv;
}

/**
 * Get version of syslib library
 *
 * @param  major   output major version number
 * @param  minor   output minor version number
 * @param  micro   output micro version number
 * @return errno return value
 */
int syslibGetVersion(int *major, int *minor, int *micro)
{
	tTokenizer t = tokenize(SYSLIB_VERSION, "-");
	if (major != NULL)
		*major = atoi(t.tokens[0]);
	if (minor != NULL)
		*minor = atoi(t.tokens[1]);
	if (micro != NULL)
		*micro = atoi(t.tokens[2]);
	tokensFree(t);

	return 0;
}

/*
 * Get revision of syslib library
 *
 * @return revision
 */
char *syslibGetRevision(void)
{
	return strdup(VERSION_REV);
}

/**
 * Internal function to set connection data
 *
 * @param  key     key to access to get connection string
 * @param  appname application name
 * @return errno return value
 */
int _optionsSetData(char *key, char *appname)
{
	int rv = 0;
	int num = 0;
	int ret = -EINVAL;
	char *tmp = NULL;

	logWrite(LOG_LEVEL_DEBUG, "%s: Setting up data = { key: '%s', app_name: '%s' }\n",
		__FUNCTION__, key, appname);

	if (strstr(key, "://") != NULL) {
		tTokenizer t = tokenize(key, "@");
		if (t.numTokens == 2) {
			num = atoi(t.tokens[0]);
			tmp = strdup(t.tokens[1]);
		}
		else
			tmp = strdup(t.tokens[0]);
		tokensFree(t);
	}
	else {
		_syslibCriticalSectionEnter();

		char *k = confGet(key);
		logWrite(LOG_LEVEL_DEBUG, "%s: Configuration key '%s' value is '%s'\n", __FUNCTION__, key, k);
		DPRINTF("%s: Configuration key '%s' value is '%s'\n", __FUNCTION__, key, k);
		//_confFree();

		_syslibCriticalSectionLeave();

		#ifdef ENABLE_CONF_DUMP
		confDump();
		#endif

		if (k == NULL) {
			logWrite(LOG_LEVEL_ERROR, "%s: Cannot read value...\n", __FUNCTION__);

			DPRINTF("%s: ERROR. K is NULL\n", __FUNCTION__);
			rv = -EINVAL;
			goto cleanup;
		}

		if (strncmp(k, "$9$", 3) == 0) {
			DPRINTF("%s: Encrypted configuration data are '%s'\n", __FUNCTION__, k);
			tmp = aesDecryptData(k + 3, NULL, 0, (k[1] == 'A') ? 1 : 0);
			DPRINTF("%s: Decrypted configuration data are '%s'\n", __FUNCTION__, tmp);
		}
		else {
			tmp = strdup(k);
			DPRINTF("%s: Plain-text configuration data are '%s'\n", __FUNCTION__, tmp);
		}
	}

	if (tmp == NULL) {
		#ifdef ALLOW_OUTPUT
		logWrite(LOG_LEVEL_ERROR, "%s: Cannot read or decrypt value\n", __FUNCTION__);
		#endif
		return -ENOENT;
	}

	char tmpNew[8192] = { 0 };
	snprintf(tmpNew, sizeof(tmpNew), "%s&application_name=%s", tmp,
		(appname != NULL) ? appname : "syslib library");

	if (pqConnect(tmpNew, NULL)) {
		DPRINTF("%s: Cannot connect to database using '%s'\n", __FUNCTION__, tmpNew);
		logWrite(LOG_LEVEL_ERROR, "%s: Connection failed\n", __FUNCTION__);
		logWrite(LOG_LEVEL_DEBUG, "%s: Cannot connect to database using '%s'\n",
			__FUNCTION__, tmpNew);
		goto cleanup;
	}

	if (num > 0) {
		DPRINTF("%s: Sleeping %d second(s)\n", __FUNCTION__, num);
		logWrite(LOG_LEVEL_DEBUG, "%s: Sleeping %d second(s)\n", __FUNCTION__, num);
		sleep(num);
	}

	ret = 0;
	_syslibSetDBConn(tmpNew);
	DPRINTF("%s: Successfully connected using connection string '%s'\n", __FUNCTION__, tmpNew);
cleanup:
	if (tmp != NULL)
		_syslibFree(tmp);

	return rv;
}

/**
 * Convert size from KiB to bytes
 *
 * @param val value to convert
 * @param unit source unit
 * @return value
 */
int syslibConvertSizeK(float val, char *unit)
{
	if (unit == NULL)
		return -1;

	int mult = 1; // kiB/s
	if (strcmp(unit, "MiB/s") == 0)
		mult = 1024;
	if (strcmp(unit, "GiB/s") == 0)
		mult = 1048576;

	return (val * mult);
}

/**
 * Internal function to identify key pressed
 *
 * @return 1 for EOF, 0 otherwise
 */
int syslibKeyPressed(void)
{
	struct termios oldt, newt;
	int ch;
	int oldf;
 
	tcgetattr(STDIN_FILENO, &oldt);
	newt = oldt;
	newt.c_lflag &= ~(ICANON | ECHO);
	tcsetattr(STDIN_FILENO, TCSANOW, &newt);
	oldf = fcntl(STDIN_FILENO, F_GETFL, 0);
	fcntl(STDIN_FILENO, F_SETFL, oldf | O_NONBLOCK);
 
	ch = getchar();
 
	tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
	fcntl(STDIN_FILENO, F_SETFL, oldf);
 
	if(ch != EOF) {
		ungetc(ch, stdin);
		return 1;
	}
 
	return 0;
}

/*
 * Check whether application is running as a shell or not
 *
 * @return boolean
 */
int syslibCheckRunningAsShell(void)
{
	int ret = 0;
	char name[1024] = { 0 };
	char path[1024] = { 0 };
	FILE *fp = NULL;

	snprintf(path, sizeof(path), "/proc/%d/cmdline", getpid());

	fp = fopen(path, "r");
	if (fp == NULL)
		return -1;
	fgets(name, sizeof(name), fp);
	fclose(fp);

	ret = (name[0] == '-');

	if (ret == 0) {
		/* If we use ForceCommand SSH daemon option we need to check another way */
		if (getenv("SHELL") != NULL) {
			if (strcmp(basename(getenv("SHELL")), name) == 0)
				ret = 1;
		}
	}

	return ret;
}

/*
 * Ensure database connection to PostgreSQL server is established
 *
 * @return None
 */
void _syslibEnsureConnection_PQ(void)
{
	int id = _syslibGetCurrent();
	if (id < 0) {
		logWrite(LOG_LEVEL_WARNING, "%s: Cannot reconnect TID #%d\n", _gettid());
		return;
	}

	if (dPQstatus(instances[id].dbconnptr) != CONNECTION_OK) {
		if (instances[id].dbconn != NULL) {
			if (pqConnect(instances[id].dbconn, NULL))
				logWrite(LOG_LEVEL_ERROR, "%s: Re-connection failed\n", __FUNCTION__);
		}
	}
}

/*
 * Ensure connection is established if applicable
 *
 * @return None
 */
void _syslibEnsureConnection(void)
{
	int id = _syslibGetCurrent();

	if (strncmp(instances[id].dbconn, "postgresql://", 13) == 0)
		_syslibEnsureConnection_PQ();
}

/**
 * Library initialization function
 *
 * @param  key     key to access to get connection string
 * @param  appname application name
 * @return errno return value
 */
int syslibInit(char *key, char *appname)
{
	int gInitDone;
	int ret = 0;

	gSMP = NULL;
	gSMP_pq = NULL;
	_sqliteLib = NULL;

	sqlite_open = NULL;
	sqlite_exec = NULL;
	sqlite_vfree = NULL;
	sqlite_close = NULL;
	sqlite_prepare = NULL;
	sqlite_step = NULL;
	sqlite_column_text = NULL;
	sqlite_finalize = NULL;

	_libpq = NULL;
	dPQsetNoticeProcessor = NULL;
	dPQstatus = NULL;
	dPQresultStatus = NULL;
	dPQntuples = NULL;
	dPQgetisnull = NULL;
	dPQexec = NULL;
	dPQconnectdb = NULL;
	dPQfname = NULL;
	dPQfinish = NULL;
	dPQerrorMessage = NULL;
	dPQnfields = NULL;
	dPQgetvalue = NULL;
	dPQclear = NULL;
	dPQstatus = NULL;

	DPRINTF("Initializing syslib version %s (TID #%d)\n",
		SYSLIB_VERSION, _gettid());

	logWrite(LOG_LEVEL_DEBUG, "Initializing syslib version %s (TID #%d)\n",
		SYSLIB_VERSION, _gettid());

	_hasPQLib = (syslibPQInit() == 0) ? 1 : 0;
	_hasSQLite = (syslibSQLiteInit() == 0) ? 1 : 0;

	gInitDone = _syslibGetInitDone();
	/* If connection initialization was already done then reuse existing connection */
	if (gInitDone == 1) {
		_syslibEnsureConnection();
		logWrite(LOG_LEVEL_DEBUG, "%s: Connection reused for TID #%d\n", __FUNCTION__, _gettid() );
		DPRINTF("%s: Connection reused for TID #%d\n", __FUNCTION__, _gettid() );
		return 0;
	}

	if ((ret = _optionsSetData(key, appname)) != 0) {
		#ifdef ALLOW_OUTPUT
		logWrite(LOG_LEVEL_ERROR, "%s: Initialization failed with error code %d\n",
			__FUNCTION__, ret);
		#endif
		DPRINTF("%s: Initialization failed\n", __FUNCTION__);
	}
	else {
		/* Set flag initialization was already done for future use */
		gInitDone = 1;
		_syslibSetInitDone(gInitDone);
		logWrite(LOG_LEVEL_DEBUG, "%s: Initialization done\n", __FUNCTION__);
		DPRINTF("%s: Initialization done\n", __FUNCTION__);
	}

	return (gInitDone) ? 0 : ret;
}

/**
 * Set logging for current thread scope
 *
 * @param  debugFile   debug file for current thread
 * @param  flags       debug flags for current thread
 * @return errno return value
 */
int syslibSetLogging(char *debugFile, int flags)
{
	int ret = 0;

	DPRINTF_CS("%s: About to enter critical section [TID #%d]\n", __FUNCTION__, _gettid() );
	_syslibCriticalSectionEnter();
	DPRINTF_CS("%s: Critical section entered [TID #%d]\n", __FUNCTION__, _gettid() );

	int id = _syslibGetCurrent();
	if (id < 0) {
		ret = 0;
		goto cleanup;
	}

	instances[id].debugFile = (debugFile == NULL) ? NULL : strdup(debugFile);
	instances[id].debugFlags = flags;
cleanup:
	DPRINTF_CS("%s: About to leave critical section [TID #%d]\n", __FUNCTION__, _gettid() );
	_syslibCriticalSectionLeave();
	DPRINTF_CS("%s: Critical section left [TID #%d]\n", __FUNCTION__, _gettid() );

	logWrite(LOG_LEVEL_INFO, "--------------------------------------------------------------\n");

	logWrite(LOG_LEVEL_INFO, "Logging facility initialized (debugFile = %s, debugFlags = %d)\n",
		debugFile, flags);

	logWrite(LOG_LEVEL_INFO, "--------------------------------------------------------------\n");

	return ret;
}

/**
 * Free library if not required anymore
 *
 * @return None
 */
void syslibFree(void)
{
	char tmp[1024] = { 0 };

	int id = _syslibGetCurrent();

	logWrite(LOG_LEVEL_DEBUG, "%s: Freeing connection for TID #%d\n", __FUNCTION__, _gettid());

	logWrite(LOG_LEVEL_INFO, "-----------------------------------\n");
	logWrite(LOG_LEVEL_INFO, "Deinitializing logging facility ...\n");
	logWrite(LOG_LEVEL_INFO, "-----------------------------------\n");

	_syslibHandleZombies();

	pqCleanup();
	//_syslibSetDBConn(NULL);
	//_syslibEntryAlterInitDone( id, 0 );
	_syslibEntryDealloc( _gettid() );

	if (nInstances == 0) {
		DPRINTF("%s: Freeing configuration space [TID #%d]\n",
			__FUNCTION__, _gettid() );

		_confFree();
	}

	syslibSQLiteFree();
	syslibPQFree();

	snprintf(tmp, sizeof(tmp), "/tmp/test.tmpd.%d", _gettid());
	unlink(tmp);
	DPRINTF("%s: Deleting %s\n", __FUNCTION__, tmp);
	snprintf(tmp, sizeof(tmp), "/tmp/test.tmpd2.%d", _gettid());
	unlink(tmp);
	DPRINTF("%s: Deleting %s\n", __FUNCTION__, tmp);

	DPRINTF("%s: Cleanup done\n", __FUNCTION__);

	logWrite(LOG_LEVEL_DEBUG, "%s: Connection freed for TID #%d\n", __FUNCTION__, _gettid());
}

/**
 * Set localization language strings path
 *
 * @param path path to set
 * @return errno value
 */
int syslibSetLocalizationPath(char *path)
{
	if (path == NULL)
		return -EINVAL;

	gLocalizationPath = strdup(path);
	return 0;
}

/**
 * Get localized string by identifier
 *
 * @param lang language to use
 * @param ident identifier
 * @return localized string
 */
char *syslibGetLocalizedString(char *lang, char *ident)
{
	char fn[1024] = { 0 };
	int canFree = 0;

	if (gLocalizationPath == NULL)
		return NULL;

	if (lang == NULL) {
		char buf[16] = { 0 };

		FILE *fpl = fopen("/tmp/language", "r");
		if (fpl != NULL) {
			fgets(buf, sizeof(buf), fpl);
			fclose(fpl);
		}

		if (strlen(buf) > 0) {
			if (buf[strlen(buf) - 1] == '\n')
				buf[strlen(buf) - 1] = 0;

			lang = strdup(buf);
		}
		else
			lang = strdup("en");

		canFree = 1;
	}

	snprintf(fn, sizeof(fn), "%s/%s", gLocalizationPath, lang);
	if (canFree == 1)
		free(lang);

	if (access(fn, F_OK) != 0)
		return strdup(ident);

	FILE *fp = fopen(fn, "r");
	if (fp == NULL)
		return strdup(ident);

	char tmp[1024] = { 0 };
	snprintf(tmp, sizeof(tmp), "%s=", ident);

	int i;
	char *ret = NULL;
	char buf[1024] = { 0 };
	while (!feof(fp)) {
		memset(buf, 0, sizeof(buf));
		fgets(buf, sizeof(buf), fp);

		if ((strlen(buf) > 0) && (buf[strlen(buf) - 1] == '\n'))
			buf[strlen(buf) - 1] = 0;

		for (i = 0; i < strlen(buf); i++) {
			if (buf[i] == '^')
				buf[i] = '\n';
			if (buf[i] == '$')
				buf[i] = '\t';
			if (buf[i] == '#')
				buf[i] = '\r';
			if (buf[i] == '~')
				buf[i] = 0;
		}

		if (strncmp(buf, tmp, strlen(tmp)) == 0)
			ret = strdup( buf + strlen(tmp) );
	}
	fclose(fp);

	if (ret == NULL)
		ret = strdup(ident);

	return ret;
}

/**
 * Print localized string by identifier
 *
 * @param lang language to use
 * @param ident identifier
 * @return None
 */
void syslibPrintLocalizedString(char *lang, char *ident)
{
	char *tmp = syslibGetLocalizedString(lang, ident);
	printf("%s", tmp); fflush(stdout);
	free(tmp);
}

/**
 * Enable or disable cursor
 *
 * @param enable state to switch cursor to
 * @return None
 */
void syslibSetCursor(int enable)
{
	char cmd[1024] = { 0 };

	snprintf(cmd, sizeof(cmd), "tput %s",
		(enable == 1) ? "cnorm" : "civis");
	system(cmd);
}

/**
 * Get DNS setup according to resolv.conf file
 *
 * @return first DNS entry from resolv.conf
 */
char *syslibGetDNSSetup(void)
{
	FILE *fp = fopen("/etc/resolv.conf", "r");
	if (fp == NULL)
		return NULL;

	char buf[1024] = { 0 };
	char *ret = NULL;
	while (!feof(fp)) {
		memset(buf, 0, sizeof(buf));
		fgets(buf, sizeof(buf), fp);

		if ((strnlen(buf, sizeof(buf)) > 0) && (buf[strlen(buf) - 1] == '\n'))
			buf[strlen(buf) - 1] = 0;

		if (strncmp(buf, "nameserver ", 11) == 0) {
			ret = strdup( buf + 11 );
			break;
		}
	}
	fclose(fp);

	return ret;
}

/**
 * Set DNS setup according to resolv.conf file
 *
 * @param dns server to set
 * @return None
 */
int syslibSetDNSSetup(char *dns)
{
	FILE *fp = fopen("/etc/resolv.conf", "w");
	if (fp == NULL)
		return -2;

	fprintf(fp, "nameserver %s\n", dns);
	fclose(fp);

	return 0;
}

/**
 * Run countdown
 *
 * @param allowBreak allow user to break countdown
 * @param sec number of seconds to count down
 * @param msgStart starting message
 * @param msgProgress progress message
 * @param msgDone terminating message
 * @return errno value
 */
int syslibRunCountdown(int allowBreak, int sec, char *msgStart, char *msgProgress, char *msgDone)
{
	int ret = 0;
	int num = sec;
	int cancel = 0;

	syslibSetCursor(0);

	printf(msgStart);
	fflush(stdout);

	while (num > 0) {
		if (syslibKeyPressed() && allowBreak)
			if (getchar() == 27) {
				cancel = 1;
				ret = 1;
				break;
		}

		if (msgProgress != NULL)
			printf(msgProgress, num);
		else {
			printf("\r");
			printf(msgStart);
		}

		fflush(stdout);
		sleep(1);
		num--;
	}

	if (msgDone != NULL)
		printf(msgDone);
	else {
		printf("\r");
		printf(msgStart);
	}

	fflush(stdout);
	syslibSetCursor(1);

	return ret;
}

/**
 * Check whether IPv4 address is valid
 *
 * @param ip IPv4 address
 * @return first DNS entry from resolv.conf
 */
int syslibIsValidIPv4(char *ip)
{
	if (ip == NULL)
		return 0;

	return ((strlen(ip) > 0) && (strcmp(ip, "0.0.0.0") != 0)) ? 1 : 0;
}

/**
 * Schedule command to run in near future
 *
 * @param cmd command to run
 * @param min time when to run in minutes
 * @return None
 */
void syslibScheduleCommand(char *cmd, int min)
{
	char scmd[1024] = { 0 };
	char *fn = tempnam("/tmp", "tmpsatXXXXXX");

	FILE *fp = fopen(fn, "w");
	if (fp != NULL) {
		fprintf(fp, "#!/bin/bash\n\n");
		fprintf(fp, "%s > /dev/null 2>&1\n", cmd);
		fclose(fp);

		chmod(fn, 0755);

		snprintf(scmd, sizeof(scmd), "at now + %d min < %s > /dev/null 2>&1", min, fn);

		int uid = setuid(0);
		system(scmd);
		unlink(fn);
		setuid(uid);
	}
}

/**
 * Do system reboot
 *
 * @return None
 */
void syslibSystemReboot(void)
{
	if (setreuid(0, 0) == -1)
		DPRINTF("%s: Cannot set UID to 0 to allow reboot\n",
			__FUNCTION__);

	int uid = setuid(0);
	system("reboot");
	setuid(uid);

	printf("Shutting down all system services ...\n");
	syslibRunCountdown(0, 60, "System is rebooting. Please wait ... ", NULL, NULL);
	reboot(RB_AUTOBOOT);
	setuid(uid);
}

/**
 * Do system shutdown
 *
 * @return None
 */
void syslibSystemShutdown(void)
{
	if (setreuid(0, 0) == -1)
		DPRINTF("%s: Cannot set UID to 0 to allow reboot\n",
			__FUNCTION__);

	int uid = setuid(0);
	system("poweroff");

	printf("Shutting down all system services ...\n");
	syslibRunCountdown(0, 60, "System is shutting down. Please wait ... ", NULL, NULL);
	reboot(0x4321fedc /*LINUX_REBOOT_CMD_POWER_OFF*/);
	setuid(uid);
}

/**
 * Change system password
 *
 * @param user username
 * @param password new password
 * @param chrootdir directory to chroot (for current system use "/")
 * @return boolean
 */
int syslibSystemChangePassword(char *user, char *password, char *chrootdir)
{
	int uid, ret;
	char tmp[1024] = { 0 };

	snprintf(tmp, sizeof(tmp), "echo -e \"%s:%s\" | chpasswd -R %s #> /dev/null 2>&1",
		user, password, chrootdir);

	uid = setuid(0);
	ret = (WEXITSTATUS(system(tmp)) == 0) ? 0 : 1;
	setuid(uid);

	return ret;
}

/**
 * Check whether user is logged-in via SSH or not
 *
 * @return boolean
 */
int syslibIsOnSSH(void)
{
	int sshUsed = 0;
	char *sshTTY = NULL;

	if ((sshTTY = getenv("SSH_TTY")) != NULL) {
		if (strcmp(ttyname(fileno(stdin)), sshTTY) == 0)
			sshUsed = 1;
		free(sshTTY);
	}

	return sshUsed;
}

/**
 * Get best encryption algorithm
 *
 * @param oSpeedEnc encryption speed
 * @param oSpeedDec decryption speed
 * @param oTimeTotal total time of analysis
 * @param message to be printed before analysis
 * @param finishMsg message to be printed after analysis
 * @return method name
 */
char *syslibGetBestCrypto(int *oSpeedEnc, int *oSpeedDec, int *oTimeTotal, char *message, char *finishMsg)
{
	tTokenizer t;
	char buf[1024] = { 0 };
	FILE *fp = NULL;
	int algoLen = 0;
	int speedEnc = 0, speedEncMax = 0;
	int speedDec = 0, speedDecMax = 0;
	char *bestAlgoName = NULL;
	time_t timeStart, timeTotal;

	if (oSpeedEnc != NULL)
		*oSpeedEnc = -1;
	if (oSpeedDec != NULL)
		*oSpeedDec = -1;
	if (oTimeTotal != NULL)
		*oTimeTotal = -1;

	printf("%s", message); fflush(stdout);

	timeStart = time(NULL);

	fp = popen("/usr/sbin/cryptsetup benchmark", "r");
	if (fp == NULL)
		return NULL;

	int ok = 0;
	while (!feof(fp)) {
		memset(buf, 0, sizeof(buf));
		fgets(buf, sizeof(buf), fp);

		if (buf[strlen(buf) - 1] == '\n')
			buf[strlen(buf) - 1] = 0;

		if (strncmp(buf, "#  Alg", 6) == 0)
			ok = 1;
		else
		if ((ok == 1) && (strlen(buf) > 0)) {
			t = tokenize(buf, " ");
			algoLen  = atoi(t.tokens[1]);
			speedEnc = syslibConvertSizeK(atof(t.tokens[2]), t.tokens[3]);
			speedDec = syslibConvertSizeK(atof(t.tokens[4]), t.tokens[5]);

			if (speedEnc > speedEncMax) {
				speedEncMax = speedEnc;
				speedDecMax = speedDec;
				free(bestAlgoName);

				char tmx[1024] = { 0 };
				snprintf(tmx, sizeof(tmx), "%s:%d", t.tokens[0], algoLen);
				bestAlgoName= strdup(tmx);
			}

			tokensFree(t);
		}
	}

	fclose(fp);

	timeTotal = time(NULL) - timeStart;

	if (oSpeedEnc != NULL)
		*oSpeedEnc = speedEnc;
	if (oSpeedDec != NULL)
		*oSpeedDec = speedDec;
	if (oTimeTotal != NULL)
		*oTimeTotal = timeTotal;

	printf("%s", finishMsg);

	return bestAlgoName;
}

/**
 * Set SSH general state
 *
 * @param state required SSH state boolean
 * @return errno value
 */
int syslibSSHGeneralStateSet(int state)
{
	int uid = setuid(0);

	if (state == 1)
		close( open(SSH_STATE_FILE, O_WRONLY | O_CREAT, 0644) );
	else
		unlink(SSH_STATE_FILE);

	setuid(uid);

	return (access(SSH_STATE_FILE, R_OK) == 0) ? 0 : -ENOENT;
}

/**
 * Get SSH general state
 *
 * @return SSH state
 */
int syslibSSHGeneralStateGet(void)
{
	return (access(SSH_STATE_FILE, R_OK) == 0) ? 1 : 0;
}

/*
 * Convert IPv4 address to it's integer representation
 *
 * @param ip IPv4 address
 * @return IPv4 address unsigned int format
 */
unsigned int syslibIPToInt(char *ip)
{
	char *ptr;
	tTokenizer t;
	int i,v,rv,idx;

	rv = 0;
	idx = 0;
	t = tokenize(ip, ".");
	for (i = 0; i < t.numTokens; i++) {
		v = strtol(t.tokens[i], &ptr, 10);
		if ((ptr != NULL) && (strlen(ptr) > 0)) {
			rv = 0;
			idx = -1;
			break;
		}
		rv += (unsigned int)(v << ((3 - idx) * 8));
		idx++;
	}
	tokensFree(t);

	return rv;
}

/*
 * Convert IPv4 unsigned int address to IPv4 string address
 *
 * @param ip IPv4 unsigned int address
 * @return IPv4 address string
 */
char *syslibIntToIP(unsigned int ip)
{
	char ret[1024] = { 0 };
	char tmp[16] = { 0 };
	int i;

	for (i = 3; i >= 0; i--) {
		memset(tmp, 0, sizeof(tmp));
		snprintf(tmp, sizeof(tmp), "%d", (ip >> (i * 8)) % 256);

		strcat(ret, tmp);
		if (i > 0)
			strcat(ret, ".");
	}

	return strdup(ret);
}

/*
 * Check whether IP address is within CIDR range
 *
 * @param ip IP address to check
 * @param cidr CIDR definition to check whether it belongs to
 * @return 0 if not within range, 1 if within range
 */
int syslibIsIPInSubnet(char *ip, char *cidr)
{
	char tmp[33] = { '0' };
	char tmp2[33] = { '0' };
	int i,v,d = 0;
	unsigned int u;
	tTokenizer t;
	char *range;
	int mask;

	t = tokenize(cidr, "/");
	if (t.numTokens == 0) {
		tokensFree(t);
		return -EINVAL;
	}
	range = strdup(t.tokens[0]);
	mask  = atoi(t.tokens[1]);
	tokensFree(t);

	u = syslibIPToInt(ip);
	for (i = 31; i >= 0; i--) {
		v = ((u & (int)(pow(2, i))) == 0) ? 0 : 1;
		tmp[d++] = (v == 0) ? '0' : '1';
		if (d == mask)
			break;
	}

	d = 0;
	u = syslibIPToInt(range);
	for (i = 31; i >= 0; i--) {
		v = ((u & (int)(pow(2, i))) == 0) ? 0 : 1;
		tmp2[d++] = (v == 0) ? '0' : '1';
		if (d == mask)
			break;
	}

	free(range);
	return (strcmp(tmp, tmp2) == 0) ? 1 : 0;
}

/*
 * Set SSH user state file and check whether file can be written
 *
 * @param fn state file, can be NULL to check permissions to write default state file
 * @return boolean
 */
int syslibSSHUserStateFileSet(char *fn)
{
	int rv;
	int canFree = 0;

	if (fn == NULL) {
		fn = strdup(SSH_STATE_FILE_USER);
		canFree = 1;
	}

	if (access(fn, F_OK) == 0)
		rv = (access(fn, W_OK) == 0) ? 0 : 1;
	else {
		FILE *fp = fopen(fn, "w");
		if (fp != NULL) {
			fclose(fp);
			unlink(fn);
			rv = 0;
		}
		else
			rv = 1;
	}

	if (rv == 0)
		gSSHUserStateFile = strdup(fn);

	if (canFree == 1)
		free(fn);

	return rv;
}

/**
 * Set SSH user state
 *
 * @param user user affected
 * @param state required SSH state boolean
 * @return errno value
 */
int syslibSSHUserStateSet(char *user, int state)
{
	int ret = 0;
	int uid = setuid(0);
	char tmp[1024] = { 0 };
	char *rets = NULL;

	snprintf(tmp, sizeof(tmp), "SELECT valid FROM ssh_user_permissions WHERE user = '%s'", user);
	rets = syslibSQLiteSelect( (gSSHUserStateFile != NULL) ? gSSHUserStateFile : SSH_STATE_FILE_USER, tmp, 0, NULL);

	if (rets == NULL)
		snprintf(tmp, sizeof(tmp), "INSERT INTO ssh_user_permissions(user, valid) VALUES('%s', %d);",
			user, state);
	else
		snprintf(tmp, sizeof(tmp), "UPDATE ssh_user_permissions SET valid = %d WHERE user = '%s'",
			state, user);

	ret = syslibSQLiteQuery( (gSSHUserStateFile != NULL) ? gSSHUserStateFile : SSH_STATE_FILE_USER, tmp, 0644);

	setuid(uid);

	return ret;
}

/**
 * Get SSH user state
 *
 * @param user user affected
 * @return SSH state
 */
int syslibSSHUserStateGet(char *user)
{
	int rv = 0;
	char *ret = NULL;
	char tmp[1024] = { 0 };
	int uid = setuid(0);

	snprintf(tmp, sizeof(tmp), "SELECT valid FROM ssh_user_permissions WHERE user = '%s'", user);
	ret = syslibSQLiteSelect((gSSHUserStateFile != NULL) ? gSSHUserStateFile : SSH_STATE_FILE_USER, tmp, 0, "1");
	if (ret != NULL)
		rv = atoi(ret);
	free(ret);

	setuid(uid);

	return rv;
}

/*
 * Create SSH user state database file
 *
 * @return creation result
 */
int syslibSSHUserStateCreate(void)
{
	int ret = 0;
	int uid = setuid(0);
	ret = syslibSQLiteQuery((gSSHUserStateFile != NULL) ? gSSHUserStateFile : SSH_STATE_FILE_USER,
		"CREATE TABLE ssh_user_permissions(user varchar(32), valid int, PRIMARY KEY(user));", 0644);
	setuid(uid);

	return ret;
}

/**
 * Set SSH user state per IP
 *
 * @param user user affected
 * @param state required SSH state boolean
 * @return errno value
 */
int syslibSSHUserStateIPSet(char *user, char *ip, int state)
{
	int ret = 0;
	int uid = setuid(0);
	char tmp[1024] = { 0 };
	char *rets = NULL;

	snprintf(tmp, sizeof(tmp), "SELECT valid FROM ssh_user_permissions_ip WHERE user = '%s' AND ip = '%s'", user, ip);
	rets = syslibSQLiteSelect((gSSHUserStateFile != NULL) ? gSSHUserStateFile : SSH_STATE_FILE_USER, tmp, 0, NULL);

	if (rets == NULL)
		snprintf(tmp, sizeof(tmp), "INSERT INTO ssh_user_permissions_ip(user, ip, valid) VALUES('%s', '%s', %d);",
			user, ip, state);
	else
		snprintf(tmp, sizeof(tmp), "UPDATE ssh_user_permissions_ip SET valid = %d, ip = '%s' WHERE user = '%s'",
			state, ip, user);
	free(rets);

	ret = syslibSQLiteQuery((gSSHUserStateFile != NULL) ? gSSHUserStateFile : SSH_STATE_FILE_USER, tmp, 0644);

	setuid(uid);

	return ret;
}

/**
 * Get SSH user state per IP
 *
 * @param user user affected
 * @return SSH state
 */
int syslibSSHUserStateIPGet(char *user, char *ip)
{
	int rv = 0;
	char *ret = NULL;
	char *rip = NULL;
	char tmp[1024] = { 0 };
	int uid = setuid(0);

	snprintf(tmp, sizeof(tmp), "SELECT valid, ip FROM ssh_user_permissions_ip WHERE user = '%s'", user);
	ret = syslibSQLiteSelect((gSSHUserStateFile != NULL) ? gSSHUserStateFile : SSH_STATE_FILE_USER, tmp, 0, "1");
	rip = syslibSQLiteSelect((gSSHUserStateFile != NULL) ? gSSHUserStateFile : SSH_STATE_FILE_USER, tmp, 1, "1");

	if (syslibIsIPInSubnet(ip, rip) == 1) {
		if (ret != NULL)
			rv = atoi(ret);
		free(ret); ret = NULL;
	}

	free(ret);
	free(rip);

	setuid(uid);

	return rv;
}

/*
 * Create SSH user state database file per IP
 *
 * @return creation result
 */
int syslibSSHUserStateIPCreate(void)
{
	int ret = 0;
	int uid = setuid(0);
	ret = syslibSQLiteQuery((gSSHUserStateFile != NULL) ? gSSHUserStateFile : SSH_STATE_FILE_USER,
		"CREATE TABLE ssh_user_permissions_ip(user varchar(32), ip varchar(20), valid int, PRIMARY KEY(user));", 0644);
	setuid(uid);

	return ret;
}

/*
 * Create SSH login message
 *
 * @return creation result
 */
int syslibSSHUserStateMsgCreate(void)
{
        int ret = 0;
        int uid = setuid(0);
        ret = syslibSQLiteQuery((gSSHUserStateFile != NULL) ? gSSHUserStateFile : SSH_STATE_FILE_USER,
                "CREATE TABLE ssh_user_message(user varchar(32), validFrom int, validTo int, msg text, PRIMARY KEY(user, validFrom));", 0644);
        setuid(uid);

        return ret;
}

/**
 * Set SSH user login for specified timestamps
 *
 * @param user user affected
 * @param state required SSH state boolean
 * @return errno value
 */
int syslibSSHUserLoginMessageSet(char *user, time_t tsFrom, time_t tsTo, char *msg)
{
	int ret = 0;
	int uid = setuid(0);
	char tmp[1024] = { 0 };
	char *rets = NULL;

	snprintf(tmp, sizeof(tmp), "SELECT msg FROM ssh_user_message WHERE validFrom = %d AND validTo = %d AND user = '%s'",
		tsFrom, tsTo, user);
	rets = syslibSQLiteSelect( (gSSHUserStateFile != NULL) ? gSSHUserStateFile : SSH_STATE_FILE_USER, tmp, 0, NULL);

	if (rets == NULL)
		snprintf(tmp, sizeof(tmp), "INSERT INTO ssh_user_message(user, validFrom, validTo, msg) VALUES('%s', %d, %d, '%s');",
			user, tsFrom, tsTo, msg);
	else
		snprintf(tmp, sizeof(tmp), "UPDATE ssh_user_message SET msg = '%s' WHERE user = '%s' AND validFrom = %d AND validTo = %d",
			msg, user, tsFrom, tsTo);

	ret = syslibSQLiteQuery( (gSSHUserStateFile != NULL) ? gSSHUserStateFile : SSH_STATE_FILE_USER, tmp, 0644);

	setuid(uid);

	return ret;
}

/**
 * Get SSH user login for specified timestamp
 *
 * @param user user affected
 * @param ts timestamp
 * @return 0 if message not present, 1 if present
 */
char *syslibSSHUserLoginMessageGet(char *user, time_t ts)
{
	int rv = 0;
	char *ret = NULL;
	char tmp[1024] = { 0 };
	int uid = setuid(0);

	snprintf(tmp, sizeof(tmp), "SELECT msg FROM ssh_user_message WHERE validFrom <= %d AND validTo >= %d AND user = '%s'",
			ts, ts, user);
	ret = syslibSQLiteSelect((gSSHUserStateFile != NULL) ? gSSHUserStateFile : SSH_STATE_FILE_USER, tmp, 0, "1");

	setuid(uid);

	return ret;
}

/*
 * Create all SSH user state databases
 *
 * @return creation result
 */
int syslibSSHUserStateCreateAll(void)
{
	int rv1, rv2, rv3;

	rv1 = syslibSSHUserStateCreate();
	rv2 = syslibSSHUserStateIPCreate();
	rv3 = syslibSSHUserStateMsgCreate();

	return ((rv1 == 0) && (rv2 == 0) && (rv3 == 0)) ? 0 : 1;
}

/*
 * Create Bash profile for user login
 *
 * @return creation result
 */
int syslibUserLoginMessageHandlerSet(void)
{
	int rv = 1;
	int uid = setuid(0);

	FILE *fp = fopen(PROFILE_USER_LOGIN, "w");
	if (fp != NULL) {
		fprintf(fp, "if [ -t 0 -a -f %s ]; then\n",
			(gSSHUserStateFile != NULL) ? gSSHUserStateFile : SSH_STATE_FILE_USER);
		fprintf(fp, "\tdt=\"$(date +%%s)\"\n");
		fprintf(fp, "\trv=1\n");
		fprintf(fp, "\twhile [ $rv != 0 ]\n");
		fprintf(fp, "\tdo\n");
		fprintf(fp, "\t\tx=\"$(sqlite3 %s \"SELECT msg FROM ssh_user_message WHERE validFrom <= $dt AND validTo >= $dt AND user = '$USER';\")\"\n",
			(gSSHUserStateFile != NULL) ? gSSHUserStateFile : SSH_STATE_FILE_USER);
		fprintf(fp, "\t\trv=$?\n");
		fprintf(fp, "\t\tif [ -z \"$x\" ]; then\n");
		fprintf(fp, "\t\t\tx=\"$(sqlite3 %s \"SELECT msg FROM ssh_user_message WHERE validFrom = -1 AND validTo = -1 AND user = '$USER';\")\"\n",
			(gSSHUserStateFile != NULL) ? gSSHUserStateFile : SSH_STATE_FILE_USER);
		fprintf(fp, "\t\t\trv=$?\n");
		fprintf(fp, "\t\tfi\n");
		fprintf(fp, "\t\techo $x\n");
		fprintf(fp, "\tdone\n");
		fprintf(fp, "fi\n");
		fclose(fp);
		rv = 0;
	}

	setuid(uid);
	return rv;
}

/*
 * Unset user login profile
 *
 * @return deletion result
 */
int syslibUserLoginMessageHandlerUnset(void)
{
	int uid = setuid(0);

	unlink(PROFILE_USER_LOGIN);

	setuid(uid);
}

/*
 * SQLite query functions
 *
 * @param filename file name of SQLite database file
 * @param query query to run upon the database
 * @param perms permissions when creating a new database
 * @return errno value
 */
int syslibSQLiteQuery(char *filename, char *query, int perms)
{
	int rc;
	sqlite3 *sql = NULL;
	char *errmsg = NULL;

	if ((sqlite_open == NULL) || (sqlite_exec == NULL) || (sqlite_vfree == NULL) || (sqlite_close == NULL)) {
		if (syslibSQLiteInit() != 0)
			return -ENOTSUP;
	}

	if (perms != 0)
		close(open(filename, O_WRONLY | O_CREAT, perms));

	rc = sqlite_open(filename, &sql);
	if (rc != 0)
		return -EINVAL;

	sqlite_exec(sql, query, NULL, NULL, &errmsg);

	if ((gSMP != NULL) && (errmsg != NULL))
		gSMP(errmsg);

	sqlite_vfree(errmsg);

	sqlite_close(sql);
	return 0;
}

/*
 * SQLite selection function
 *
 * @param filename file name of SQLite database file
 * @param query query to run upon the SQLite database file
 * @param idx index of row to return
 * @param def default value if not found
 * @return return value
 */
char *syslibSQLiteSelect(char *filename, char *query, int idx, char *def)
{
	int rc = 0;
	char *ret = NULL;
	sqlite3 *db;
	sqlite3_stmt *res;

	if ((sqlite_open == NULL) || (sqlite_exec == NULL) || (sqlite_vfree == NULL) || (sqlite_close == NULL)
		|| (sqlite_prepare == NULL) || (sqlite_step == NULL) || (sqlite_column_text == NULL)
		|| (sqlite_finalize == NULL)) {
		if (syslibSQLiteInit() != 0)
			return (ret != NULL) ? strdup(def) : NULL;
	}

	rc = sqlite_open(filename, &db);
	if (rc != 0)
		return (ret != NULL) ? strdup(def) : NULL;
    
	rc = sqlite_prepare(db, query, -1, &res, 0);    
	if (rc != 0) {
		sqlite_close(db);
		return (ret != NULL) ? strdup(def) : NULL;
	}

	rc = sqlite_step(res);
	if (rc == SQLITE_ROW) {
		const unsigned char *fld = sqlite_column_text(res, idx);
		if (fld != NULL)
			ret = strdup(fld);
	}

	sqlite_finalize(res);
	sqlite_close(db);

	return (ret != NULL) ? ret : ((def != NULL) ? strdup(def) : NULL);
}

/*
 * Set SQLite message processor
 *
 * @param func sqlite message processor function
 */
void syslibSQLiteSetMessageProcessor(tSQLiteMessageFunc func)
{
	gSMP = func;
}

/*
 * Initialize SQLite functions
 *
 * @return errno value
 */
int syslibSQLiteInit(void)
{
	_sqliteLib = dlopen("libsqlite3.so", RTLD_LAZY);
	if (_sqliteLib == NULL)
		return -ENOENT;
	sqlite_open = dlsym(_sqliteLib, "sqlite3_open");
	sqlite_exec = dlsym(_sqliteLib, "sqlite3_exec");
	sqlite_vfree = dlsym(_sqliteLib, "sqlite3_free");
	sqlite_close = dlsym(_sqliteLib, "sqlite3_close");
	sqlite_step = dlsym(_sqliteLib, "sqlite3_step");
	sqlite_prepare = dlsym(_sqliteLib, "sqlite3_prepare_v2");
	sqlite_column_text = dlsym(_sqliteLib, "sqlite3_column_text");
	sqlite_finalize = dlsym(_sqliteLib, "sqlite3_finalize");
	if ((sqlite_open == NULL) || (sqlite_exec == NULL) || (sqlite_vfree == NULL) || (sqlite_close == NULL)
		|| (sqlite_prepare == NULL) || (sqlite_step == NULL) || (sqlite_column_text == NULL)
		|| (sqlite_finalize == NULL)) {
		dlerror();
		dlclose(_sqliteLib);
		return -ENOENT;
	}

	return 0;
}

/*
 * Free SQLite functions
 */
void syslibSQLiteFree(void)
{
	if (_hasSQLite == 1)
		if (_sqliteLib != NULL)
			dlclose(_sqliteLib);
	_hasSQLite = 0;
	free(gSSHUserStateFile);
}

/*
 * Get information whether there's SQLite present on the system
 *
 * @return boolean
 */
int syslibHasSQLite(void)
{
	return _hasSQLite;
}

/*
 * Initialize libPQ functions
 *
 * @return errno value
 */
int syslibPQInit(void)
{
	_libpq = dlopen("libpq.so", RTLD_LAZY);
	if (_libpq == NULL)
		return -ENOENT;
	dPQsetNoticeProcessor = dlsym(_libpq, "PQsetNoticeProcessor");
	dPQstatus = dlsym(_libpq, "PQstatus");
	dPQresultStatus = dlsym(_libpq, "PQresultStatus");
	dPQntuples = dlsym(_libpq, "PQntuples");
	dPQgetisnull = dlsym(_libpq, "PQgetisnull");
	dPQexec = dlsym(_libpq, "PQexec");
	dPQconnectdb = dlsym(_libpq, "PQconnectdb");
	dPQfname = dlsym(_libpq, "PQfname");
	dPQfinish = dlsym(_libpq, "PQfinish");
	dPQerrorMessage = dlsym(_libpq, "PQerrorMessage");
	dPQnfields = dlsym(_libpq, "PQnfields");
	dPQgetvalue = dlsym(_libpq, "PQgetvalue");
	dPQclear = dlsym(_libpq, "PQclear");

	if ((dPQsetNoticeProcessor == NULL) || (dPQstatus == NULL) || (dPQresultStatus == NULL) || (dPQntuples == NULL)
		|| (dPQgetisnull == NULL) || (dPQexec == NULL) || (dPQconnectdb == NULL) || (dPQfname == NULL)
		|| (dPQfinish == NULL) || (dPQerrorMessage == NULL) || (dPQnfields == NULL) || (dPQgetvalue == NULL)
		|| (dPQclear == NULL)) {
		dlerror();
		dlclose(_libpq);
		return -ENOENT;
	}

	return 0;
}

/*
 * Free SQLite functions
 */
void syslibPQFree(void)
{
	if (_hasPQLib == 1)
		if (_libpq != NULL)
			dlclose(_libpq);

	_hasPQLib = 0;
}

/*
 * Get information whether there's libpq present on the system
 *
 * @return boolean
 */
int syslibHasPQLib(void)
{
	return _hasPQLib;
}

void syslibPQSetMessageProcessor(PQnoticeProcessor func)
{
        gSMP_pq = func;
}

#ifdef HAS_TEST_MAIN
/**
 * SQLite message processor
 *
 * @param msg message from the SQLite library
 */
void sqlite_message_processor(char *msg)
{
        printf("%s: %s\n", __FUNCTION__, msg);
}

void pq_message_processor(void *arg, const char *message)
{
	if (message == NULL)
		return;

	char *msg = strdup(message);
	msg[strlen(msg) - 1] = 0;
	if ((arg != NULL) && (strcmp(arg, "ERROR") == 0))
		printf("%s: Error received: '%s'\n", __FUNCTION__, msg);
	else
		printf("%s: Notice received '%s'\n", __FUNCTION__, msg);
	free(msg);
}

/**
 * Binary entry point if compiled as standard binary and not shared object
 *
 * @return application return value
 */
int main()
{
	//if (syslibInit("postgresql://localhost:5432/test?user=test&password=test", NULL, (void *)pq_message_processor) != 0) {
	if (syslibInit("postgresql://localhost:5432/test?user=test&password=test", NULL) != 0) {
		printf("Error: Cannot initialize database connection\n");
		return 1;
	}

	printf("IP address 192.168.122.1 is %u\n", syslibIPToInt("192.168.122.1"));

	char *ip = syslibIntToIP(3232266753);
	printf("IP address decimal %u is %s\n", 3232266753, ip);
	free(ip);

	printf("IP address 192.168.1.123 is in the 192.168.1.0/24 subnet: %d\n",
		syslibIsIPInSubnet("192.168.1.123", "192.168.1.0/24"));

	printf("IP address 192.168.1.123 is in the 192.168.0.0/24 subnet: %d\n",
		syslibIsIPInSubnet("192.168.1.123", "192.168.0.0/24"));

	printf("IP address 192.168.1.123 is in the 192.168.0.0/16 subnet: %d\n",
		syslibIsIPInSubnet("192.168.1.123", "192.168.0.0/16"));

	printf("IP address 192.168.1.123 is in the 192.168.1.240/28 subnet: %d\n",
		syslibIsIPInSubnet("192.168.1.123", "192.168.1.240/28"));

	printf("IP address 192.168.1.245 is in the 192.168.1.240/28 subnet: %d\n",
		syslibIsIPInSubnet("192.168.1.245", "192.168.1.240/28"));

	printf("IP address 192.168.1.244 is in the 192.168.1.245/32 subnet: %d\n",
		syslibIsIPInSubnet("192.168.1.244", "192.168.1.245/32"));

	printf("IP address 192.168.1.245 is in the 192.168.1.245/32 subnet: %d\n",
		syslibIsIPInSubnet("192.168.1.245", "192.168.1.245/32"));

	if (syslibHasSQLite()) {
		char *ret = NULL;

		if (syslibSSHUserStateFileSet("/tmp/ssh-user.db") != 0)
			printf("WARNING: SSH User state file cannot be written\n");

		syslibSSHUserStateCreateAll();

		if (syslibUserLoginMessageHandlerSet() != 0)
			printf("WARNING: Cannot set login message handler\n");

		if (syslibUserLoginMessageHandlerUnset() != 0)
			printf("WARNING: Cannot unset login message handler\n");

		syslibSSHUserStateIPSet("user", "192.168.122.1/24", 1);
		printf("%sllowing user 'user' IP address 192.168.122.10\n",
			(syslibSSHUserStateIPGet("user", "192.168.122.10") == 0) ? "Disa" : "A");
		printf("%sllowing user 'user' IP address 192.168.1.10\n",
			(syslibSSHUserStateIPGet("user", "192.168.1.10") == 0) ? "Disa" : "A");

		printf("Testing SQLite library functions ...\n");
		syslibSQLiteSetMessageProcessor(sqlite_message_processor);

		syslibSQLiteQuery("/tmp/test-sqlite.db", "CREATE TABLE test(id int, val int, PRIMARY KEY(id))", 0644);
		syslibSQLiteQuery("/tmp/test-sqlite.db", "INSERT INTO test(id, val) VALUES(3, 4294967296)", 0644);
		ret = syslibSQLiteSelect("/tmp/test-sqlite.db", "SELECT val FROM test WHERE id = 3", 0, NULL);
		printf("Select query returned: %s [/tmp/test-sqlite.db]\n", ret);
		free(ret); ret = NULL;

		printf("... done\n");
	}
	else
		printf("SQLite not found on the system\n");

	if (syslibHasPQLib() == 1) {
		char noticeTest[] = "DO language plpgsql $$\n"
				"BEGIN\n"
				"  RAISE NOTICE 'Test notice';\n"
				"END\n"
				"$$;";

		syslibPQSetMessageProcessor(pq_message_processor);

		printf("Running '%s' on database system.\n", "INSERT INTO test(id, val) VALUES(5, 'test2')");
		syslibQueryExecute("INSERT INTO test(id, val) VALUES(5, 'test2')", NULL);
		syslibQueryExecute(noticeTest, NULL);
		printf("... done\n");
	}
	else
		printf("Cannot find libpq on the system\n");

	syslibFree();
	return 0;
}
#endif
