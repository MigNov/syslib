#include "syslib.h"

//#define DEBUG_DATABASE

#ifdef DEBUG_DATABASE
#define DPRINTF(fmt, ...) \
do { fprintf(stderr, "[debug/database ] " fmt , ## __VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) \
do {} while(0)
#endif

void PQdebugNoticeProcessor(void *arg, const char *message)
{
	if (message == NULL)
		return;

	char *msg = strdup(message);
	msg[strlen(msg) - 1] = 0;
	DPRINTF("%s: Notice received '%s'\n", __FUNCTION__, msg);
	free(msg);
}

int pqConnect(char *connstr, PGconn *conn)
{
	int	ret = -1;

	if (_hasPQLib != 1)
		return -1;

	DPRINTF("%s: Initializing database connection to PgSQL database [TID #%d]\n",
		__FUNCTION__, _gettid());

	// connstr = aesDecryptData(confGet("DBConnSM") + 3, NULL, 0);

	if (conn == NULL) {
		DPRINTF("%s: Connection pointer is NULL [TID #%d]\n",
			__FUNCTION__, _gettid());

		if (connstr != NULL) {
			DPRINTF("%s: Connection string is '%s' [TID #%d]\n",
				__FUNCTION__, connstr, _gettid());

			conn = dPQconnectdb(connstr);

			DPRINTF("%s: Connection pointer is 0x%p [TID #%d]\n",
				__FUNCTION__, conn, _gettid());
		}

		if (conn == NULL) {
			DPRINTF("%s: Connection pointer is NULL [TID #%d]\n",
				__FUNCTION__, _gettid());
			dPQfinish(conn);
			DPRINTF("%s: Returning -EINVAL [TID #%d]\n",
				__FUNCTION__, _gettid());
			return -EINVAL;
		}
	}

	if (dPQsetNoticeProcessor != NULL) {
		if (gSMP_pq != NULL)
			dPQsetNoticeProcessor(conn, gSMP_pq, NULL);
		else
			dPQsetNoticeProcessor(conn, PQdebugNoticeProcessor, NULL);
	}

	if (dPQstatus(conn) != CONNECTION_OK) {
		DPRINTF("%s: Connection failed (%s) [TID #%d]\n", __FUNCTION__,
			dPQerrorMessage(conn), _gettid());
		libLogToFile(LOG_ERROR, "%s: Connection failed (%s) [TID #%d]\n", __FUNCTION__,
			dPQerrorMessage(conn), _gettid() );

		if (gSMP_pq != NULL)
			gSMP_pq("ERROR", dPQerrorMessage(conn));
	}
	else {
		DPRINTF("%s: Connection successful [TID #%d]\n",
			__FUNCTION__, _gettid());
		_syslibSetDBConnPtr( (void *)conn );
		ret = 0;
	}

	return ret;
}

void pqCleanup(void)
{
	if (_hasPQLib != 1)
		return;

	char *connstr = _syslibGetDBConn();
	if (connstr == NULL)
		return;

	if (strncmp(connstr, "postgresql://", 13) != 0) {
		free(connstr);
		return;
	}

	PGconn *pgconn = NULL;
	DPRINTF("%s: Finishing connection pointer to PgSQL [TID #%d]\n",
		__FUNCTION__, _gettid() );
	pgconn = (PGconn *)_syslibGetDBConnPtr();
	if (pgconn != NULL) {
		if (dPQfinish != NULL)
			dPQfinish(pgconn);
	}

	pgconn = NULL;
	_syslibSetDBConnPtr(pgconn);
}

char *pqSelect(char *query, char *field)
{
	char		*ret = NULL;
	PGresult        *res = NULL;
	PGconn          *conn = NULL;
	struct timeval	tv1, tv2;
	float		tsec = 0.0;

	if (_hasPQLib != 1)
		return NULL;

	char *connstr = _syslibGetDBConn();
	if (connstr == NULL)
		return NULL;

	if (strncmp(connstr, "postgresql://", 13) != 0) {
		free(connstr);
		return NULL;
	}

	conn = (PGconn *)_syslibGetDBConnPtr();
	if (conn == NULL) {
		DPRINTF("%s: Connection pointer is NULL, (re)connecting ... [TID #%d]\n",
			__FUNCTION__, _gettid());

		pqCleanup();
		char *gDBConn = _syslibGetDBConn();
		if (gDBConn == NULL) {
			DPRINTF("%s: Cannot reconnect [TID #%d]\n",
				__FUNCTION__, _gettid() );
			return NULL;
		}

		if (pqConnect(gDBConn, NULL) != 0) {
			DPRINTF("%s: Cannot connect to call pqSelect [TID #%d]\n",
				__FUNCTION__, _gettid() );
			pqCleanup();
			return NULL;
		}
	}

	DPRINTF("%s: Query is \"%s\" [TID #%d]\n",
		__FUNCTION__, query, _gettid());

	libLogToFile(LOG_SQL, "%s: Query is '%s'\n",
		__FUNCTION__, query);

	gettimeofday(&tv1, NULL);

        tsec =  (((tv1.tv_sec * 1000000) + tv1.tv_usec) -
                ((tv2.tv_sec * 1000000) + tv2.tv_usec)) / 1000000.;

	_syslibEnsureConnection();
	if (dPQsetNoticeProcessor != NULL) {
		if (gSMP_pq != NULL)
			dPQsetNoticeProcessor(conn, gSMP_pq, NULL);
		else
			dPQsetNoticeProcessor(conn, PQdebugNoticeProcessor, NULL);
	}
	res = dPQexec(conn, query);
	if (dPQresultStatus(res) != PGRES_TUPLES_OK) {
		DPRINTF("%s: Query failed (%s) [TID #%d]\n", __FUNCTION__,
			dPQerrorMessage(conn), _gettid() );

		if (gSMP_pq != NULL)
			gSMP_pq("ERROR", dPQerrorMessage(conn));

//		pqCleanup();
		return NULL;
	}

	gettimeofday(&tv2, NULL);

	tsec =  (((tv2.tv_sec * 1000000) + tv2.tv_usec) -
		((tv1.tv_sec * 1000000) + tv1.tv_usec)) / 1000.;

	int idxFld = -1, i, j, nFields;
	nFields = dPQnfields(res);
	for (i = 0; i < nFields; i++)
		if (strcmp(dPQfname(res, i), field) == 0) {
			idxFld = i;
			break;
		}

	if (idxFld > -1) {
		for (i = 0; i < dPQntuples(res); i++) {
			for (j = 0; j < nFields; j++) {
				char *tmp = dPQgetvalue(res, i, idxFld);
				if (tmp != NULL) {
					libLogToFile(LOG_SQL, "%s: Query result is '%s'\n",
						__FUNCTION__, tmp);
					ret = strdup(tmp);
				}
			}
		}
	}
	else
		libLogToFile(LOG_SQL, "%s: Index for field '%s' not found\n",
			__FUNCTION__, field);

	dPQclear(res);

	DPRINTF("%s: Query '%s' returned '%s' [TID #%d]\n",
		__FUNCTION__, query, ret, _gettid() );
	libLogToFile(LOG_SQL, "[%6.1f ms] %s: Query '%s' returned '%s'\n", tsec, __FUNCTION__, query, ret);
	return ret;
}

tQueryResult pqSelectAdvanced(char *query, int numFields, char **fields)
{
	char		*ret = NULL;
	PGresult        *res = NULL;
	PGconn          *conn = NULL;
	struct timeval	tv1, tv2;
	float		tsec = 0.0;
	int		c, d;
	tQueryResult	retv;

	retv.nRows = 0;
	retv.rows = NULL;

	if (_hasPQLib != 1)
		return retv;

	conn = (PGconn *)_syslibGetDBConnPtr();
	if (conn == NULL) {
		DPRINTF("%s: Connection pointer is NULL, (re)connecting ... [TID #%d]\n",
			__FUNCTION__, _gettid());

		pqCleanup();
		char *gDBConn = _syslibGetDBConn();
		if (gDBConn == NULL) {
			DPRINTF("%s: Cannot reconnect [TID #%d]\n",
				__FUNCTION__, _gettid() );
			return retv;
		}

		if (pqConnect(gDBConn, NULL) != 0) {
			DPRINTF("%s: Cannot connect to call pqSelect [TID #%d]\n",
				__FUNCTION__, _gettid() );
			pqCleanup();
			return retv;
		}
	}

	DPRINTF("%s: Query is \"%s\" [TID #%d]\n",
		__FUNCTION__, query, _gettid());

	libLogToFile(LOG_SQL, "%s: Query is '%s'\n",
		__FUNCTION__, query);

	gettimeofday(&tv1, NULL);

        tsec =  (((tv1.tv_sec * 1000000) + tv1.tv_usec) -
                ((tv2.tv_sec * 1000000) + tv2.tv_usec)) / 1000000.;

	_syslibEnsureConnection();
	if (dPQsetNoticeProcessor != NULL) {
		if (gSMP_pq != NULL)
			dPQsetNoticeProcessor(conn, gSMP_pq, NULL);
		else
			dPQsetNoticeProcessor(conn, PQdebugNoticeProcessor, NULL);
	}
	res = dPQexec(conn, query);
	if (dPQresultStatus(res) != PGRES_TUPLES_OK) {
		DPRINTF("%s: Query failed (%s) [TID #%d]\n", __FUNCTION__,
			dPQerrorMessage(conn), _gettid() );

		if (gSMP_pq != NULL)
			gSMP_pq("ERROR", dPQerrorMessage(conn));

//		pqCleanup();
		return retv;
	}

	gettimeofday(&tv2, NULL);

	tsec =  (((tv2.tv_sec * 1000000) + tv2.tv_usec) -
		((tv1.tv_sec * 1000000) + tv1.tv_usec)) / 1000.;

	int numRows = dPQntuples(res);

	retv.nRows = numRows;
	retv.rows = (tQueryRow *)malloc( numRows * sizeof(tQueryRow) );
	if (retv.rows == NULL)
		return retv;

	for (d = 0; d < numRows; d++) {
		retv.rows[d].nFields = numFields;
		retv.rows[d].fields = (tQueryField *)malloc( numFields * sizeof(tQueryField) );

		if (retv.rows[d].fields == NULL)
			goto cleanup;

		for (c = 0; c < numFields; c++) {
			int idxFld = -1, i, j, nFields;
			nFields = dPQnfields(res);
			for (i = 0; i < nFields; i++)
				if (strcmp(dPQfname(res, i), fields[c]) == 0) {
					idxFld = i;
					break;
				}

			if (idxFld > -1) {
				char *tmp = dPQgetvalue(res, d, idxFld);
				if (tmp != NULL) {
					libLogToFile(LOG_SQL, "%s: Query result is '%s'\n",
						__FUNCTION__, tmp);
					retv.rows[d].fields[c].name = strdup(fields[c]);

					if (dPQgetisnull(res, d, idxFld) == 1)
						retv.rows[d].fields[c].val = NULL;
					else
						retv.rows[d].fields[c].val = strdup(tmp);

					if ((strlen(tmp) > 1) && (tmp[0] == '{') && (tmp[strlen(tmp) - 1] == '}')) {
						char *tmp2 = strdup(tmp);
						*tmp2++;
						tmp2[strlen(tmp2) - 1] = 0;

						tTokenizer t = tokenize(tmp2, ",");
						retv.rows[d].fields[c].nParsedVals = t.numTokens;
						retv.rows[d].fields[c].parsedVals = (char **)malloc( t.numTokens * sizeof(char *) );
						for (j = 0; j < t.numTokens; j++)
							retv.rows[d].fields[c].parsedVals[j] = strdup(t.tokens[j]);
						tokensFree(t);
					}
					else {
						retv.rows[d].fields[c].nParsedVals = 0;
						retv.rows[d].fields[c].parsedVals = NULL;
					}
				}
				else
					retv.rows[d].fields[c].name = NULL;
			}
			else
				libLogToFile(LOG_SQL, "%s: Index for field '%s' not found\n",
					__FUNCTION__, fields[c]);
		}
	}

	dPQclear(res);

	DPRINTF("%s: Query '%s' returned '%s' [TID #%d]\n",
		__FUNCTION__, query, ret, _gettid() );
	libLogToFile(LOG_SQL, "[%6.1f ms] %s: Query '%s' returned '%s'\n", tsec, __FUNCTION__, query, ret);

	goto end;
cleanup:
	free(retv.rows[0].fields);
	retv.nRows = 0;
end:
	return retv;
}

void freeQueryResult(tQueryResult r)
{
	int i, j, k;

	for (i = 0; i < r.nRows; i++) {
		for (j = 0; j < r.rows[i].nFields; j++) {
			for (k = 0; k < r.rows[i].fields[j].nParsedVals; k++)
				free(r.rows[i].fields[j].parsedVals[k]);
			free(r.rows[i].fields[j].name);
			free(r.rows[i].fields[j].val);
			free(r.rows[i].fields[j].parsedVals);

			r.rows[i].fields[j].nParsedVals = 0;
		}
		r.rows[i].nFields = 0;
		free(r.rows[i].fields);
	}
	free(r.rows);
	r.nRows = 0;
}

int pqExecute(char *query)
{
        char            *ret = NULL;
        PGresult        *res = NULL;
        PGconn          *conn = NULL;
	struct timeval	tv1, tv2;
	float		tsec = 0.0;

	if (_hasPQLib != 1)
		return -1;

	conn = (PGconn *)_syslibGetDBConnPtr();
        if (conn == NULL) {
		DPRINTF("%s: Connection pointer is NULL, (re)connecting ...\n", __FUNCTION__);

		pqCleanup();

		char *gDBConn = _syslibGetDBConn();
		if (gDBConn == NULL) {
			DPRINTF("%s: (Re)connection failed\n", __FUNCTION__);
			return -EINVAL;
		}

		if (pqConnect(gDBConn, NULL) != 0) {
			pqCleanup();
			libLogToFile(LOG_ERROR, "%s: Connection to database failed\n", __FUNCTION__);
                	return -EINVAL;
		}
	}

	_syslibEnsureConnection();
        DPRINTF("%s: Query is '%s'\n", __FUNCTION__, query);
	libLogToFile(LOG_SQL, "%s: Query is '%s'\n", __FUNCTION__, query);

	gettimeofday(&tv1, NULL);
	if (dPQsetNoticeProcessor != NULL) {
		if (gSMP_pq != NULL)
			dPQsetNoticeProcessor(conn, gSMP_pq, NULL);
		else
			dPQsetNoticeProcessor(conn, PQdebugNoticeProcessor, NULL);
	}
        res = dPQexec(conn, query);
        if ((dPQresultStatus(res) != PGRES_COMMAND_OK) && (dPQresultStatus(res) != PGRES_TUPLES_OK)){
		dPQclear(res);
                DPRINTF("%s: Query failed (%s)\n", __FUNCTION__,
                        PQerrorMessage(conn));
		libLogToFile(LOG_ERROR, "%s: Query failed (%s)\n", __FUNCTION__,
			dPQerrorMessage(conn));

		if (gSMP_pq != NULL)
			gSMP_pq("ERROR", dPQerrorMessage(conn));

//                pqCleanup();
                return -EINVAL;
        }

	dPQclear(res);

	gettimeofday(&tv2, NULL);
	tsec =  (((tv2.tv_sec * 1000000) + tv2.tv_usec) -
		((tv1.tv_sec * 1000000) + tv1.tv_usec)) / 1000.;

	libLogToFile(LOG_SQL, "[%6.1f ms] %s: Query '%s' finished\n", tsec, __FUNCTION__, query);

	return 0;
}

