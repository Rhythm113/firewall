CC = gcc
CFLAGS = -O2 -Wall -DBUILD_USERSPACE -pthread -DHAS_YARA -I../kernel
LDFLAGS = -lyara -pthread

SRCS = test_runner.c \
       ../kernel/http_inspect.c \
       ../kernel/ip_blocklist.c \
       ../kernel/tcp_monitor.c \
       ../kernel/sqli_detect.c \
       ../kernel/cmdi_detect.c \
       ../kernel/path_detect.c \
       ../kernel/bot_detect.c \
       ../kernel/ip_reputation.c \
       ../kernel/yara_engine.c \
       ../kernel/ebpf_xdp.c
OBJS = test_runner.o \
       http_inspect.o \
       ip_blocklist.o \
       tcp_monitor.o \
       sqli_detect.o \
       cmdi_detect.o \
       path_detect.o \
       bot_detect.o \
       ip_reputation.o \
       yara_engine.o \
       ebpf_xdp.o
TARGET = test_runner

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $(TARGET) $(LDFLAGS)

test_runner.o: test_runner.c
	$(CC) $(CFLAGS) -c test_runner.c -o test_runner.o

%.o: ../kernel/%.c
	$(CC) $(CFLAGS) -c $< -o $@

run:
	./$(TARGET)

clean:
	rm -f $(TARGET) *.o
