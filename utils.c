#include "syslib.h"

//#define DEBUG_UTILS

#ifdef DEBUG_UTILS
#define DPRINTF(fmt, ...) \
do { fprintf(stderr, "[debug/utils    ] " fmt , ## __VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) \
do {} while(0)
#endif

// Debug open functions family:
//   - fopen
//   - fclose
//   - popen
//   - open
//   - socket
//   - close
//
//#define DEBUG_OPEN_FUNCS

typedef struct tCommandCache {
	char *cmd;
	char *valueStr;
	unsigned long long value;
	time_t time;
} tCommandCache;

int _ncache = 0;
tCommandCache *_ccache = NULL;

int oldclosed = 0;
int oldpackets = 0;
int olddrops = 0;
int olddecode = 0;

int gInetStream = -1;

int cacheAdd(char *cmd, char *valueStr, unsigned long long value)
{
	if ((_ccache == NULL) || (_ncache == 0))
		_ccache = (tCommandCache *)malloc( sizeof(tCommandCache) );
	else
		_ccache = (tCommandCache *)realloc( _ccache, (_ncache + 1) * sizeof(tCommandCache) );

	if (_ccache == NULL)
		return 1;

	_ccache[_ncache].cmd = strdup(cmd);
	_ccache[_ncache].valueStr = (valueStr != NULL) ? strdup(valueStr) : NULL;
	_ccache[_ncache].value = value;
	_ccache[_ncache].time = time(NULL);
	_ncache++;
	return 0;
}

char *cacheLookupStr(char *cmd, int nolimit)
{
	int i;

	if (_ccache == NULL)
		return NULL;

	for (i = 0; i < _ncache; i++) {
		if ((strcmp(_ccache[i].cmd, cmd) == 0) && ((_ccache[i].time == time(NULL)
				|| (nolimit)))) {
			return _ccache[i].valueStr;
		}
	}

	return NULL;
}

unsigned long long cacheLookupInt(char *cmd, int nolimit)
{
	int i;

	if (_ccache == NULL)
		return 12345;

	for (i = 0; i < _ncache; i++) {
		if ((strcmp(_ccache[i].cmd, cmd) == 0) && ((_ccache[i].time == time(NULL)
				|| (nolimit)))) {
//			DPRINTF("%s: Found command cache for '%s' on index %d\n", __FUNCTION__, cmd, i);
			return _ccache[i].value;
		}
	}

//	DPRINTF("%s: Cache miss for command '%s'\n", __FUNCTION__, cmd);
	return 12345;
}

int cacheOverwriteInt(char *cmd, unsigned long long value)
{
	int i;

	if (_ccache == NULL)
		return 1;

	for (i = 0; i < _ncache; i++) {
		if (strcmp(_ccache[i].cmd, cmd) == 0) {
			_ccache[i].value = value;
			return 0;
		}
	}

	return 1;
}

char *get_datetime(void)
{
	char *outstr = NULL;
	time_t t;
	struct tm *tmp;

	t = time(NULL);
	tmp = localtime(&t);
	if (tmp == NULL)
		return NULL;

	outstr = (char *)malloc( 32 * sizeof(char) );
	if (strftime(outstr, 32, "%Y-%m-%d %H:%M:%S", tmp) == 0)
		return NULL;

	return outstr;
}

void libLogToFile(int logType, const char *fmt,...)
{
	// TODO: Add mutex for logging to enable
	return;

	va_list arglist;
	char *fn = NULL;
		return;

	FILE *fp = fopen(fn, "a");
	if (fp == NULL)
		return;

	char *tmp = get_datetime();

	va_start( arglist, fmt );
	fprintf(fp, "[%s] ", tmp);
	vfprintf( fp, fmt, arglist );
	va_end( arglist );

	free(tmp);

	fclose(fp);
}

FILE *dfopen(const char *fn, const char *mode)
{
#ifndef DEBUG_OPEN_FUNCS
	return fopen(fn, mode);
#else
	FILE *fp = NULL;

	fp = fopen(fn, mode);
	if (fp == NULL)
		libLogToFile(LOG_DEBUG, "[DBGOPEN] %s: Filename '%s' cannot be opened with mode '%s' (errno %d)\n",
			__FUNCTION__, fn, mode, errno);
	else
		libLogToFile(LOG_DEBUG, "[DBGOPEN] %s: Filename '%s' opened with mode '%s' as pointer %p\n",
			__FUNCTION__, fn, mode, fp);
	return fp;
#endif
}

int dfclose(FILE *fp)
{
#ifndef DEBUG_OPEN_FUNCS
	return fclose(fp);
#else
	int ret = EBADF;

	if (fp == NULL) {
		libLogToFile(LOG_DEBUG, "[DBGOPEN] %s: Pointer is NULL\n",
			__FUNCTION__);

		return ret;
	}

	ret = fclose(fp);
	if (ret == 0)
		libLogToFile(LOG_DEBUG, "[DBGOPEN] %s: File identified by pointer %p closed with return code %d\n",
			__FUNCTION__, fp);
	else
		libLogToFile(LOG_DEBUG, "[DBGOPEN] %s: File identified by pointer %p not closed (errno %d)\n",
			__FUNCTION__, fp, errno);
	fp = NULL;
	return ret;
#endif
}

FILE *dpopen(const char *command, const char *type)
{
#ifndef DEBUG_OPEN_FUNCS
	return popen(command, type);
#else
	FILE *fp = NULL;

	fp = popen(command, type);
	if (fp == NULL)
		libLogToFile(LOG_DEBUG, "[DBGOPEN] %s: Command '%s' cannot be opened with mode '%s' (errno %d)\n",
			__FUNCTION__, command, type, errno);
	else
		libLogToFile(LOG_DEBUG, "[DBGOPEN] %s: Command '%s' opened with mode '%s' as pointer %p\n",
			__FUNCTION__, command, type, fp);
	return fp;
#endif
}

int dsocket(int domain, int type, int protocol)
{
	int ret = -1;

#ifndef DEBUG_OPEN_FUNCS
	if ((domain == AF_INET) && (type == SOCK_STREAM) && (protocol == 0)) {
		if (gInetStream == -1) {
			ret = socket(domain, type, protocol);

			gInetStream = ret;
			return ret;
		}
		else
			return gInetStream;
	}

	ret = socket(domain, type, protocol);
	fcntl(ret, F_SETFD, FD_CLOEXEC);
	return ret;
#else
	if ((domain == AF_INET) && (type == SOCK_STREAM) && (protocol == 0)) {
		if (gInetStream == -1) {
			ret = socket(domain, type, protocol);

			gInetStream = ret;
			return ret;
		}
		else
			return gInetStream;
	}

	ret = socket(domain, type, protocol);
	fcntl(ret, F_SETFD, FD_CLOEXEC);
	if (ret > -1)
		libLogToFile(LOG_DEBUG, "[DBGOPEN] %s: Socket(%d, %d, %d) opened as #%d\n",
			__FUNCTION__, domain, type, protocol, ret);
	else {
		libLogToFile(LOG_DEBUG, "[DBGOPEN] %s: Socket(%d, %d, %d) cannot be opened (errno %d)\n",
			__FUNCTION__, domain, type, protocol, errno);
	}

	return ret;
#endif
}

int dopen(const char *pathname, int flags)
{
#ifndef DEBUG_OPEN_FUNCS
	return open(pathname, flags);
#else
	int ret = -1;

	ret = open(pathname, flags);
	if (ret > -1)
		libLogToFile(LOG_DEBUG, "[DBGOPEN] %s: Open(%s, %d) opened as #%d\n",
			__FUNCTION__, pathname, flags, ret);
	else
		libLogToFile(LOG_DEBUG, "[DBGOPEN] %s: Open(%s, %d) cannot be opened (errno %d)\n",
			__FUNCTION__, pathname, flags, errno);

	return ret;
#endif
}

int dclose(int fd)
{
#ifndef DEBUG_OPEN_FUNCS
	return close(fd);
#else
	int ret = -1;

	libLogToFile(LOG_DEBUG, "[DBGOPEN] %s: Closing socket #%d\n",
		__FUNCTION__, fd);

	ret = close(fd);
	if (ret > -1)
		libLogToFile(LOG_DEBUG, "[DBGOPEN] %s: Socket #%d closed\n",
			__FUNCTION__, fd);
	else
		libLogToFile(LOG_DEBUG, "[DBGOPEN] %s: Socket #%d cannot be closed (errno %d)\n",
			__FUNCTION__, fd, errno);
	return ret;
#endif
}

int cacheOverwriteStr(char *cmd, char *value)
{
        int i;

        if (_ccache == NULL)
                return 1;

        for (i = 0; i < _ncache; i++) {
                if (strcmp(_ccache[i].cmd, cmd) == 0) {
			free(_ccache[i].valueStr);
                        _ccache[i].valueStr = (value != NULL) ? strdup(value) : NULL;
                        return 0;
                }
        }

        return 1;
}

int cacheUpdateInt(char *cmd, unsigned long long value)
{
	if (cacheLookupInt(cmd, 1) == 12345) {
//		DPRINTF("%s: Command '%s' not found.\n", __FUNCTION__, cmd);
		cacheAdd(cmd, NULL, value);
	}
	else {
//		DPRINTF("%s: Command '%s' found.\n", __FUNCTION__, cmd);
		cacheOverwriteInt(cmd, value);
	}

	return 0;
}

int cacheUpdateStr(char *cmd, char *value)
{
	if (cacheLookupStr(cmd, 1) == NULL) {
//              DPRINTF("%s: Command '%s' not found.\n", __FUNCTION__, cmd);
		cacheAdd(cmd, value, 0);
	}
	else {
//              DPRINTF("%s: Command '%s' found.\n", __FUNCTION__, cmd);
		cacheOverwriteStr(cmd, value);
	}

	return 0;
}

int cacheUpdate(char *cmd, char *valueStr, unsigned long long value)
{
	if (valueStr == NULL)
		cacheUpdateInt(cmd, value);
	else
		cacheUpdateStr(cmd, valueStr);

	return 0;
}

void cacheDump(void)
{
	int i;

	if (_ccache == NULL)
		return;

	for (i = 0; i < _ncache; i++) {
		printf("Cache entry #%d:\n", i + 1);
		printf("\tCommand: %s\n", _ccache[i].cmd);
		if (_ccache[i].valueStr == NULL)
			printf("\tValue: %llu\n", _ccache[i].value);
		else
			printf("\tValue: '%s'\n",  _ccache[i].valueStr);
		printf("\tTime: %d\n", _ccache[i].time);
	}
}

void cacheFree(void)
{
	int i;

	if (_ccache == NULL)
		return;

	for (i = 0; i < _ncache; i++) {
		free(_ccache[i].cmd);

//		if (_ccache[i].valueStr != NULL)
//			free(_ccache[i].valueStr);
	}

	free(_ccache);
	_ncache = 0;
}

int getCommandOutputSize(char *cmd, int ignoreStderr, int newUid)
{
	int total = -1;
	FILE *fp = NULL;
	char tmp[1024];
	int olduid = -1, new_fd = -1, backup_fd = -1;

	if (ignoreStderr) {
		new_fd = dopen("/dev/null", O_WRONLY);
		backup_fd = dup(2);
		dup2(new_fd, 2);
	}

	if (newUid >= 0) {
		errno = 0;
		olduid = setuid(newUid);
		if (errno != 0) {
			DPRINTF("%s: Cannot set UID to %d (%s)\n",
				__FUNCTION__, newUid, -errno, strerror(errno));
			goto cleanup;
		}
	}

	fp = dpopen(cmd, "r");
	if (fp == NULL) {
		DPRINTF("%s: Cannot open '%s'\n", __FUNCTION__, cmd);
		goto cleanup;
	}

	total = 0;
	while (!feof(fp)) {
		memset(tmp, 0, sizeof(tmp));
		fgets(tmp, sizeof(tmp), fp);
		total += strlen(tmp);
	}
	dfclose(fp);
cleanup:
	if (olduid != -1)
		setuid(olduid);
	if (ignoreStderr) {
		close(new_fd);
		dup2(backup_fd, 2);
		close(backup_fd);
	}

	return total;
}

char *getCommandOutput(char *cmd, int ignoreStderr, int newUid)
{
	int total = 0;
	FILE *fp = NULL;
	char *ret = NULL;
	char *tbuf = NULL;
	char tmp[1024] = { 0 };
	int olduid = -1, new_fd = -1, backup_fd = -1;

	if (ignoreStderr) {
		new_fd = dopen("/dev/null", O_WRONLY);
		backup_fd = dup(2);
		dup2(new_fd, 2);
	}

	if (newUid >= 0) {
		errno = 0;
		olduid = setuid(newUid);
		if (errno != 0) {
			libLogToFile(LOG_DEBUG, "%s: Cannot set UID to %d, errno %d (%s)\n",
				__FUNCTION__, newUid, -errno, strerror(errno));
			DPRINTF("%s: Cannot set UID to %d, errno %d (%s)\n",
				__FUNCTION__, newUid, -errno, strerror(errno));
			goto cleanup;
		}
		else
			libLogToFile(LOG_DEBUG, "%s: UID changed to %d\n",
				__FUNCTION__, newUid);
	}

	libLogToFile(LOG_DEBUG, "%s: Getting size for '%s' (ignore stderr %d, new uid %d)\n",
		__FUNCTION__, cmd, ignoreStderr, newUid);
	total = getCommandOutputSize(cmd, ignoreStderr, newUid);
	total++;

	libLogToFile(LOG_DEBUG, "%s: Size for '%s' = %d\n",
		__FUNCTION__, cmd, total);

	// Hack but try it
	if (total == 0) {
		libLogToFile(LOG_DEBUG, "%s: Size is zero, try to recover\n",
			__FUNCTION__, cmd, total);
	}

	fp = dpopen(cmd, "r");
	if (fp == NULL) {
		libLogToFile(LOG_DEBUG, "%s: Cannot open '%s'\n",
			__FUNCTION__, cmd);
		DPRINTF("%s: Cannot open '%s'\n", __FUNCTION__, cmd);
		goto cleanup;
	}

	tbuf = (char *)malloc( total * sizeof(char) );
	memset(tbuf, 0, total * sizeof(char) );
	while (!feof(fp)) {
		memset(tmp, 0, sizeof(tmp));
		fgets(tmp, sizeof(tmp), fp);

		strcat(tbuf, tmp);
	}

	dfclose(fp);

	tbuf[strlen(tbuf) - 1] = 0;
	if (strlen(tbuf) > 0) {
		libLogToFile(LOG_DEBUG, "%s: Duplicating temporary buffer to return value\n",
			__FUNCTION__);
		ret = strdup(tbuf);
	}

	free(tbuf);
	tbuf = NULL;
cleanup:
	libLogToFile(LOG_DEBUG, "%s: Cleaning up\n",
		__FUNCTION__);

	if (olduid != -1)
		setuid(olduid);
	if (ignoreStderr) {
		close(new_fd);
		dup2(backup_fd, 2);
		close(backup_fd);
	}

	return ret;
}

char *getMACAddress(char *iface)
{
	char ret[16] = { 0 };
	char tmp[4] = { 0 };
	struct ifreq s;
	int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

	strcpy(s.ifr_name, iface);
	if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
		int i;
		for (i = 0; i < 6; i++) {
			snprintf(tmp, sizeof(tmp), "%02x:",
				(unsigned char) s.ifr_addr.sa_data[i]);
			strcat(ret, tmp);
		}
		if (strlen(ret) > 0)
			ret[strlen(ret) - 1] = 0;

		return strdup(ret);
	}

	return NULL;
}

void ensureOSRelease(void)
{
        FILE *fp = fopen("/etc/os-release", "w");
        if (fp != NULL) {
                fprintf(fp, "NAME=\"TrustPort OS\"\n");
                fprintf(fp, "VERSION=\"TrustPort OS\"\n");
                fprintf(fp, "ID=\"trustos\"\n");
                fprintf(fp, "ID_LIKE=\"rhel fedora\"\n");
                fprintf(fp, "VERSION_ID=\"1\"\n");
                fprintf(fp, "PRETTY_NAME=\"TrustPort OS\"\n");
                fprintf(fp, "ANSI_COLOR=\"0;32\"\n");
                fprintf(fp, "CPE_NAME=\"cpe:/o:trustport:os:1\"\n");
                fprintf(fp, "HOME_URL=\"https://www.trustport.com/\"\n");
                fprintf(fp, "BUG_REPORT_URL=\"https://bugs.trustport.com\"\n");
                fclose(fp);
        }

        fp = fopen("/etc/centos-release", "w");
        if (fp != NULL) {
		printf("CENT\n");
                fprintf(fp, "TrustPort OS\n");
                fclose(fp);
        }

        fp = fopen("/etc/redhat-release", "w");
        if (fp != NULL) {
                fprintf(fp, "TrustPort OS\n");
                fclose(fp);
        }

        fp = fopen("/etc/system-release", "w");
        if (fp != NULL) {
                fprintf(fp, "TrustPort OS\n");
                fclose(fp);
        }

        fp = fopen("/etc/system-release-cpe", "w");
        if (fp != NULL) {
                fprintf(fp, "cpe:/o:trustport:os:1\n");
                fclose(fp);
        }
}

int tokenizeNumTokens(char *string, char *by)
{
	char *tmp;
	char *str;
	char *save;
	char *token;
	int i = 0;
	tTokenizer t;

	if (string == NULL)
		return 0;

	tmp = strdup(string);
	for (str = tmp; ; str = NULL) {
		token = strtok_r(str, by, &save);
		if (token == NULL)
			break;

		i++;
	}
	free(tmp);

	return i;
}

tTokenizer tokenize(char *string, char *by)
{
	char *tmp;
	char *str;
	char *save;
	char *token;
	int i = 0;
	int num = 0;
	tTokenizer t;

	if (string == NULL) {
		t.numTokens = 0;
		return t;
	}

	num = tokenizeNumTokens(string, by);

	tmp = strdup(string);
	t.tokens = (char **)malloc( num * sizeof(char *) );
	if (t.tokens == NULL) {
		t.numTokens = 0;
		return t;
	}

	for (str = tmp; ; str = NULL) {
		token = strtok_r(str, by, &save);
		if (token == NULL)
			break;

		t.tokens[i++] = strdup(token);
	}
	free(tmp);

	t.numTokens = i;
	return t;
}

void tokensFree(tTokenizer t)
{
	int i;

	for (i = 0; i < t.numTokens; i++)
		free(t.tokens[i]);

	free(t.tokens);
}

char *decbin(int n)
{
	char ret[10] = { 0 };

	snprintf(ret, sizeof(ret), "%d%d%d%d%d%d%d%d",
		((n & 128) == 0) ? 0 : 1,
		((n & 64) == 0) ? 0 : 1,
		((n & 32) == 0) ? 0 : 1,
		((n & 16) == 0) ? 0 : 1,
		((n & 8) == 0) ? 0 : 1,
		((n & 4) == 0) ? 0 : 1,
		((n & 2) == 0) ? 0 : 1,
		((n & 1) == 0) ? 0 : 1,
		n % 2);

	return strdup(ret);
}

void printfTab(const char* format, ...)
{
	int i;
	int tabLen = LENTAB;
	va_list arglist;
	char tmp[2] = { 0 };
	char tmptab[128] = { 0 };
	char tmptab2[128] = { 0 };
	char fmtstr[4096] = { 0 };

	for (i = 0; i < tabLen; i++) {
		strcat(tmptab, " ");
		strcat(tmptab2, "-");
	}
	for (i = 0; i < strlen(format); i++) {
		if (format[i] == 9) // \t
			strcat(fmtstr, tmptab);
		else
		if (format[i] == 27) // \e
			strcat(fmtstr, tmptab2);
		else {
			tmp[0] = format[i];
			strcat(fmtstr, tmp);
		}
	}

	va_start( arglist, format );
	vprintf( fmtstr, arglist );
	va_end( arglist );
}

time_t getMTime(char *filename)
{
	int free_me = 0;
	struct stat st;

	if (filename == NULL) {
		char tmp[1024] = { 0 };
		char tmp2[1024] = { 0 };
		FILE *fp = NULL;

		snprintf(tmp, sizeof(tmp), "/proc/%d/exe",
			getpid());

		readlink(tmp, tmp2, sizeof(tmp2));
		filename = strdup(tmp2);
		free_me = 1;
	}

	if (access(filename, R_OK) != 0) {
		DPRINTF("%s: File '%s' inaccessible\n",
			__FUNCTION__, filename);
		return -1;
	}

	stat(filename, &st);

	if (free_me == 1)
		free(filename);

	return st.st_mtime;
}

int systemGetThreads(void)
{
	return sysconf(_SC_NPROCESSORS_ONLN);
}

unsigned long systemGetMemory(void)
{
	unsigned long mem = -1;
	const long pagesz = sysconf(_SC_PAGESIZE);
	const long pages = sysconf(_SC_PHYS_PAGES);

	if ((pagesz != -1) && (pages != 1))
		mem = ((unsigned long long)(pagesz) * (unsigned long long)(pages)) / 1048576;

	return mem;
}

int _confLoad(char *filename)
{
	char *tmp = NULL;
	char line[4096] = { 0 };

	FILE *fp = dfopen(filename, "r");
	if (fp == NULL)
		return -errno;

	while (!feof(fp)) {
		memset(line, 0, sizeof(line));
		fgets(line, sizeof(line), fp);
		if (strlen(line) > 0) {
			/* Lines beginning by # are comments */
			if (line[0] == '#')
				continue;
			if (line[strlen(line) - 1] == '\n')
				line[strlen(line) - 1] = 0;

			if ((tmp = strstr(line, "=")) != NULL) {
				int i;
				char *tmp2;

				*tmp++;
				i = strlen(line) - strlen(tmp);
				tmp2 = strdup(line);
				tmp2[i-1] = 0;

				if (_confVars == NULL) {
					DPRINTF("%s: Allocating configuration space\n", __FUNCTION__);
					_confVars = (tCV *)malloc( sizeof(tCV) );
				}
				else {
					DPRINTF("%s: Reallocating configuration space to %d element(s)\n",
						__FUNCTION__, (_nConfVars + 1));

					_confVars = (tCV *)realloc( _confVars,
						(_nConfVars + 1) * sizeof(tCV));

					if (_confVars == NULL)
						DPRINTF("%s: Reallocation of configuration space failed\n",
							__FUNCTION__);
				}
				_confVars[_nConfVars].key = strdup(tmp2);
				_confVars[_nConfVars].value = strdup(tmp);
				_nConfVars++;
				DPRINTF("Adding configuration variable '%s' with value '%s'\n",
					tmp2, tmp);
			}
		}
	}
	dfclose(fp);

	DPRINTF("Added %d configuration variables\n", _nConfVars);
	return 0;
}

void _confFree(void)
{
	int i, j = 0;

	if (_confVars == NULL) {
		DPRINTF("%s: No configuration entries freed\n", __FUNCTION__);
		return;
	}

	_syslibConfCriticalSectionEnter();

	for (i = 0; i < _nConfVars; i++) {
		DPRINTF("%s: Cleaning up entry #%d\n",
			__FUNCTION__, i + 1);
		free(_confVars[i].key);
		free(_confVars[i].value);
		_confVars[i].key = NULL;
		_confVars[i].value = NULL;
		j++;
	}

	DPRINTF("%s: All freed. Freeing confVars structure\n", __FUNCTION__);
	free(_confVars);
	_confVars = NULL;
	_nConfVars = 0;

	_syslibConfCriticalSectionLeave();
	DPRINTF("%s: %d configuration entries freed\n", __FUNCTION__, j);
}

unsigned long long getCommandOutputULLong(char *cmd)
{
	float tsec;
	char *ret = NULL;
	struct timeval tv1, tv2;
	unsigned long long rv = 0;

	if (cacheLookupInt(cmd, 0) != 12345)
		return cacheLookupInt(cmd, 0);

	gettimeofday(&tv1, NULL);
	ret = getCommandOutput(cmd, 0, -1);
	if (ret == NULL)
		return -1;

	rv = strtoull(ret, NULL, 10);
	free(ret);

	gettimeofday(&tv2, NULL);
	tsec =	(((tv2.tv_sec * 1000000) + tv2.tv_usec) -
		((tv1.tv_sec * 1000000) + tv1.tv_usec)) / 1000.;

	cacheUpdate(cmd, NULL, rv);
	DPRINTF("[%6.1f ms] %s('%s') returned %llu\n",
		__FUNCTION__, tsec, cmd, rv);
	return rv;
}

unsigned long long getMemoryUsedUserspace(void)
{
	return getCommandOutputULLong("python -c 'print '$(ps aux | awk '{sum += $6} END { print sum }')' * 1024'");
}

unsigned long long getMemoryFree(void)
{
	return getCommandOutputULLong("python -c \"print $(cat /proc/meminfo | grep \"MemFree:\" | awk '{split($0, a, \" \"); print a[2]}')L * 1024L\"");
}

unsigned long long getMemoryTotal(void)
{
	return getCommandOutputULLong("python -c \"print $(cat /proc/meminfo | grep \"MemTotal:\" | awk '{split($0, a, \" \"); print a[2]}')L * 1024L\"");
}

unsigned long long getMemoryCache(void)
{
	return getCommandOutputULLong("python -c \"print $(cat /proc/meminfo | grep \"^Cached:\" | awk '{split($0, a, \" \"); print a[2]}')L * 1024L\"");
}

unsigned long long getMemoryBuffers(void)
{
	return getCommandOutputULLong("python -c \"print $(cat /proc/meminfo | grep Buffers: | awk '{split($0, a, \" \"); print a[2]}')L * 1024L\"");
}

unsigned long long getMemorySwapFree(void)
{
	return getCommandOutputULLong("python -c \"print $(cat /proc/meminfo | grep SwapFree: | awk '{split($0, a, \" \"); print a[2]}')L * 1024L\"");
}

unsigned long long getMemorySwapTotal(void)
{
	return getCommandOutputULLong("python -c \"print $(cat /proc/meminfo | grep SwapTotal: | awk '{split($0, a, \" \"); print a[2]}')L * 1024L\"");
}

unsigned long long getMemoryUsed(void)
{
	return getMemoryTotal() - getMemoryFree();
}

unsigned long long getMemoryUsedKernel(void)
{
	unsigned long long memUSUse = getMemoryUsedUserspace();
	unsigned long long memUse = getMemoryUsed();
	unsigned long long ret = (memUse > memUSUse) ? memUse - memUSUse : memUSUse - memUse;

	return ret;
}

int getMemory(unsigned long long *memTotal, unsigned long long *memFree, unsigned long long *memUsed,
	unsigned long long *memKernel, unsigned long long *memUserspace, unsigned long long *memBuffers,
	unsigned long long *memCache, unsigned long long *swapFree, unsigned long long *swapUsed)
{
	unsigned long long v1 = getMemoryTotal();
	unsigned long long v2 = getMemoryFree();
	unsigned long long v3 = getMemoryUsed();
	unsigned long long v4 = getMemoryUsedKernel();
	unsigned long long v5 = getMemoryUsedUserspace();

	if (v5 > v3) {
		unsigned long long a = v3;
		v3 = v5;
		v5 = a;
	}

	//v2 = (v1 > v3) ? v1 - v3 : v3 - v1;
	if (memTotal)
		*memTotal = v1;
	if (memFree)
		*memFree = v2;
	if (memUsed)
		*memUsed = /*v3*/v1 - v2;
	if (memKernel)
		*memKernel = v4;
	if (memUserspace)
		*memUserspace = v5;
	if (memCache)
		*memCache = getMemoryCache();
	if (memBuffers)
		*memBuffers = getMemoryBuffers();
	if (swapFree)
		*swapFree = getMemorySwapFree();
	if (swapUsed)
		*swapUsed = getMemorySwapTotal() - getMemorySwapFree();

	return 0;
}

long _gettid(void)
{
	return (long)syscall (SYS_gettid);
}

unsigned long long getPartitionSize(char *mp)
{
	char cmd[1024] = { 0 };

	snprintf(cmd, sizeof(cmd), "python -c 'print '$(stat --file-system --format=%%s %s)'L * '$(stat --file-system --format=%%b %s)'L'", mp, mp);
	return getCommandOutputULLong(cmd);
}

unsigned long long getPartitionUsed(char *mp)
{
	char cmd[1024] = { 0 };

	snprintf(cmd, sizeof(cmd), "python -c 'print '$(stat --file-system --format=%%s %s)'L * '$(stat --file-system --format=%%f %s)'L'", mp, mp);
	return getCommandOutputULLong(cmd);
}

void getPartitionInfo(char *mp, unsigned long long *pTotal, unsigned long long *pFree, unsigned long long *pUsed)
{
	unsigned long long partTotal, partFree, partUsed;

	partTotal = getPartitionSize(mp);
	partFree = getPartitionUsed(mp);
	partUsed = partTotal - partFree;

	if (pTotal)
		*pTotal = partTotal;
	if (pFree)
		*pFree = partFree;
	if (pUsed)
		*pUsed = partUsed;
}

float getPartitionUsage(char *mp)
{
	char cmd[1024] = { 0 };
	char *ret = NULL;
	int bs, bf, bt;

	snprintf(cmd, sizeof(cmd), "stat --file-system --format=%%s %s", mp);
	ret = getCommandOutput(cmd, 0, -1);

	if (ret == NULL)
		return 0.00;

	bs = atoi(ret);
	free(ret);

	snprintf(cmd, sizeof(cmd), "stat --file-system --format=%%f %s", mp);
	ret = getCommandOutput(cmd, 0, -1);

	if (ret == NULL)
		return 0.00;

	bf = atoi(ret);
	free(ret);

	snprintf(cmd, sizeof(cmd), "stat --file-system --format=%%b %s", mp);
	ret = getCommandOutput(cmd, 0, -1);

	if (ret == NULL)
		return 0.00;

	bt = atoi(ret);
	free(ret);

	return ((bt - bf) / (bt / 100.)) + 1;
}

void confDump(void)
{
	int i;

	_syslibConfCriticalSectionEnter();

	if (_confVars == NULL) {
		DPRINTF("%s: Configuration not loaded yet. Nothing to dump ... [TID #%d]\n",
			__FUNCTION__, _gettid() );
		return;
	}

	DPRINTF("%s: Configuration variable count is %d [TID #%d]\n",
		__FUNCTION__, _nConfVars, _gettid() );

	for (i = 0; i < _nConfVars; i++) {
		DPRINTF("%s: Accessing entry #%d [TID #%d]\n", __FUNCTION__, i, _gettid() );
		DPRINTF("%s: \tKey '%s': '%s'\n", __FUNCTION__, _confVars[i].key, _confVars[i].value);
	}

	_syslibConfCriticalSectionLeave();
}

char *confGet(char *key)
{
	int i;
	char *ret = NULL;

	if (_confVars == NULL) {
		DPRINTF("%s: Configuration not loaded yet. Loading now ... [TID #%d]\n",
			__FUNCTION__, _gettid() );
		_syslibConfCriticalSectionEnter();
		if (_confLoad((getenv(CONF_VAR) != NULL) ? getenv(CONF_VAR) : CONF_FILE) != 0) {
			DPRINTF("%s: Cannot load configuration from '%s' [TID #%d]\n",
				__FUNCTION__, CONF_FILE, _gettid() );
			errno = EPERM;
			goto cleanup;
		}
		_syslibConfCriticalSectionLeave();
	}

	DPRINTF("%s: Getting configuration information for '%s' [TID #%d] ...\n",
		__FUNCTION__, key, _gettid() );

	DPRINTF("%s: Configuration variable count is %d [TID #%d]\n",
		__FUNCTION__, _nConfVars, _gettid() );

	_syslibConfCriticalSectionEnter();
	for (i = 0; i < _nConfVars; i++) {
		DPRINTF("%s: Accessing entry #%d [TID #%d]\n", __FUNCTION__, i, _gettid() );
		if (_confVars == NULL)
			DPRINTF("%s: Error accessing entry #%d [TID #%d]\n", __FUNCTION__, i, _gettid() );

		if ((_confVars != NULL) && (strcmp(_confVars[i].key, key) == 0)) {
			DPRINTF("Configuration variable for '%s' has value '%s'\n",
				_confVars[i].key, _confVars[i].value);
			ret = _confVars[i].value;
			goto cleanup;
		}
	}

cleanup:
	_syslibConfCriticalSectionLeave();

	if (ret == NULL)
		DPRINTF("%s: Configuration variable '%s' is undefined [TID #%d]\n",
			__FUNCTION__, key, _gettid() );
	else
		DPRINTF("%s: Configuration variable for '%s' returning value '%s'\n",
			__FUNCTION__, _confVars[i].key, _confVars[i].value);

	return ret;
}

/*
char *systemGetUUID(void)
{
	char cmd[1024] = { 0 };
	snprintf(cmd, sizeof(cmd), "dmidecode | grep UUID | awk '{split($0, a, \": \"); print a[2]}'");

	char *ret = getCommandOutput(cmd, 1, 0);
	DPRINTF("%s: System UUID is '%s'\n", __FUNCTION__, ret);
	return ret;
}
*/

char *ltrim(char *str)
{
	while (!isprint(*str))
		*str++;

	return str;
}

void clearScreen(void)
{
	DPRINTF("Clearing screen ...\n");
	system("clear");
}

char *getFileContents(char *fn)
{
	char line[1024] = { 0 };

	FILE *fp = dfopen(fn, "r");
	if (fp == NULL)
		return NULL;
	fgets(line, sizeof(line), fp);
	if (line[strlen(line) - 1] == '\n')
		line[strlen(line) - 1] = 0;
	dfclose(fp);

	return strdup(line);
}

char *getConnectionString(char *typ)
{
	char *pgConn = confGet(typ);

	if (pgConn == NULL)
		return NULL;

	if (strncmp(pgConn, "$9$", 3) == 0) {
		char *tmp = aesDecryptData(pgConn + 3, NULL, 0);
		free(pgConn);
		pgConn = tmp;
	}

	return pgConn;
}

