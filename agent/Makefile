# Makefile for fw_agent

CC = gcc
CFLAGS = -O2 -Wall
LDFLAGS = -pthread

all: fw_agent

fw_agent: fw_agent.c pgp_wrapper.c
	$(CC) $(CFLAGS) fw_agent.c pgp_wrapper.c -o fw_agent $(LDFLAGS)

clean:
	rm -f fw_agent *.o
