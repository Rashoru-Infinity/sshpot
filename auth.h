#ifndef AUTH_H
#define AUTH_H

#include <libssh/libssh.h>
#include <stdbool.h>

#define MAXBUF 100

typedef struct connection connection;
typedef struct dbinfo dbinfo;

struct connection {
    ssh_session session;
    ssh_message message;
    char client_ip[MAXBUF];
    char con_time[MAXBUF];
    char *user;
    char *pass;
};

struct dbinfo {
	bool enable_sql;
	char *host;
	char *user;
	char *password;
	char *db_name;
	unsigned int port;
};

int handle_auth(ssh_session session, dbinfo db);
int report_to_sql(connection *c, dbinfo db);

#endif
