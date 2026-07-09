# Makefile for soc_receiver

CC = gcc
CFLAGS = -O2 -Wall
LDFLAGS = -lsqlite3 -lcrypto -lcrypt -pthread

all: soc_receiver

soc_receiver: soc_receiver.c db.c auth.c pgp_wrapper.c
	$(CC) $(CFLAGS) soc_receiver.c db.c auth.c pgp_wrapper.c -o soc_receiver $(LDFLAGS)

clean:
	rm -f soc_receiver *.o
