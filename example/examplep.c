#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>

#include "../include/syslib.h"

#define MAX_THREADS	128

long _gettid(void);

void sqlite_message_processor(char *msg)
{
        printf("[TID %5d] %s: %s\n", _gettid(), __FUNCTION__, msg);
}

void read_from_db(int num)
{
	int rv = 0;
	char *rvc = NULL;

	rv = syslibInit("DBConnSM", NULL);
	syslibSetLogging("EXP", LOG_LEVEL_ALL);
	if (rv != 0) {
		printf("[TID %5d] syslibInit returned %d\n", _gettid(), rv);
		return;
	}

	if (num == 0)
		printf("[TID %5d] IP address 192.168.122.1 is %u\n", _gettid(), syslibIPToInt("192.168.122.1"));

	if (syslibHasSQLite()) {
		char *ret = NULL;

		printf("[TID %5d] Testing SQLite library functions ...\n", _gettid());
		syslibSQLiteSetMessageProcessor(sqlite_message_processor);

		syslibSQLiteQuery("/tmp/test-sqlite.db", "CREATE TABLE test(id int, val int, PRIMARY KEY(id))", 0644);
		syslibSQLiteQuery("/tmp/test-sqlite.db", "INSERT INTO test(id, val) VALUES(3, 4294967296)", 0644);
		ret = syslibSQLiteSelect("/tmp/test-sqlite.db", "SELECT val FROM test WHERE id = 3", 0, NULL);
		printf("[TID %5d] Select query returned: %s [/tmp/test-sqlite.db]\n", _gettid(), ret);

		printf("[TID %5d] ... done\n", _gettid() );
	}
	else
		printf("[TID %5d] SQLite not found on the system\n", _gettid() );

	//syslibFree();

	return;
}

void *run_thread(void *arg)
{
	int i;
	int num = ((int *)arg);

	for (i = 0; i < 20; i++)
		read_from_db(num + i);

	//syslibFree();

	int ret = 0;
	pthread_exit((void *)ret);
}

void exitFunc(void)
{
	syslibFree();
}

int main(int argc, char *argv[])
{
	int i, rc;
	pthread_t thr[MAX_THREADS];
	char tmp[1024] = { 0 };
	void *status = 0;

	atexit(exitFunc);

	srand(time(NULL));
	for (i = 0; i < MAX_THREADS; i++) {
		printf("[PID %5d] Running thread #%d\n", getpid(), i);

		pthread_create(&thr[i], NULL, run_thread, (void *)i);
		pthread_join(thr[i], &status);
		rc = (int)status;
		if (rc != 0) {
			printf("Operation failed\n");
			return 1;
		}
	}

	if ((argc > 1) && (strncmp(argv[1], "--no-wait", 9) == 0))
		return 0;

	for (i = 0; i < MAX_THREADS; i++)
		pthread_join(thr[i], NULL);

	return 0;
}

