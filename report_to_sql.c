#include "auth.h"

#include <stdlib.h>
#include <string.h>

#include <mysql/mysql.h>

int report_to_sql(struct connection *c, struct dbinfo db) {
	MYSQL *conn = NULL;
	MYSQL_BIND bind[4];
	MYSQL_STMT *stmt;
	long unsigned int data_size[4];
	int status;
	const char *stmt_proto = "INSERT INTO ATTACKLOG VALUES(TIMESTAMP(?), \
	      ?, ?, ?);";

	conn = mysql_init(NULL);
	if (!mysql_real_connect(conn, db.host, db.user, db.password, \
				db.db_name, db.port, NULL, 0)) {
		return 1;
	}

	if (!(stmt = mysql_stmt_init(conn))) {
		mysql_close(conn);
		return 1;
	}

	if (mysql_stmt_prepare(stmt, stmt_proto, strlen(stmt_proto))) {
		mysql_close(conn);
		mysql_stmt_close(stmt);
		return 1;
	}

	memset(bind, 0, sizeof(MYSQL_BIND) * 4);

	bind[0].buffer_type = MYSQL_TYPE_STRING;	
	bind[0].buffer = c->con_time;
	data_size[0] = (long unsigned int)strlen(c->con_time);
	bind[0].length = data_size;
	bind[0].is_null = 0;

	bind[1].buffer_type = MYSQL_TYPE_STRING;
	bind[1].buffer = c->client_ip;
	data_size[1] = (long unsigned int)strlen(c->client_ip);
	bind[1].length = data_size + 1;
	bind[1].is_null = 0;

	bind[2].buffer_type = MYSQL_TYPE_STRING;
	bind[2].buffer = c->user;
	data_size[2] = (long unsigned int)strlen(c->user);
	bind[2].length = data_size + 2;
	bind[2].is_null = 0;

	bind[3].buffer_type = MYSQL_TYPE_STRING;
	bind[3].buffer = c->pass;
	data_size[3] = (long unsigned int)strlen(c->pass);
	bind[3].length = data_size + 3;
	bind[3].is_null = 0;

	if ((status = mysql_stmt_bind_param(stmt, bind))) {
		mysql_close(conn);
		mysql_stmt_close(stmt);
		return status;
	}

	if ((status = mysql_stmt_execute(stmt))) {
		mysql_close(conn);
		mysql_stmt_close(stmt);
		return status;
	}
	
	mysql_close(conn);
	mysql_stmt_close(stmt);
	return 0;
}
