# Makefile for Nullsploit soc_receiver

CC = gcc
CFLAGS = -O2 -Wall
LDFLAGS = -lpq -lcurl -lcrypto -lcrypt -pthread

all: soc_receiver

soc_receiver: soc_receiver.c db.c auth.c pgp_wrapper.c threat_intel.c
	$(CC) $(CFLAGS) soc_receiver.c db.c auth.c pgp_wrapper.c threat_intel.c -o soc_receiver $(LDFLAGS)

clean:
	rm -f soc_receiver *.o
