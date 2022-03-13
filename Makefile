CC = gcc
CFLAGS = -g -Wall
CHMOD := $(shell which chmod)
SETCAP := $(shell which setcap)
USER := $(shell whoami)

all: sshpot

sshpot: main.o auth.o report_to_sql.o
	$(CC) $(CFLAGS) $^ -lssh -lmysqlclient -o $@

main.o: main.c config.h
	$(CC) $(CFLAGS) -c main.c

auth.o: auth.c auth.h config.h
	$(CC) $(CFLAGS) -c auth.c

report_to_sql.o: report_to_sql.c auth.h
	$(CC) $(CFLAGS) -c report_to_sql.c

install:
	@if [ $(USER) != "root" ]; then echo make install must be run as root.; false; fi
	$(CHMOD) 755 sshpot
	$(SETCAP) 'cap_net_bind_service=+ep' sshpot

clean:
	\/bin/rm -f *.o
