# Makefile for Nullsploit WAF kernel / userspace modules

CC = gcc
CFLAGS = -O2 -Wall -DBUILD_USERSPACE -pthread -DHAS_YARA
LDFLAGS = -lnetfilter_queue -lyara -pthread

# If eBPF/XDP is enabled
# CFLAGS += -DHAS_EBPF
# LDFLAGS += -lbpf

all: fw_nfq

fw_nfq: fw_nfq.c ip_blocklist.c http_inspect.c tcp_monitor.c sqli_detect.c cmdi_detect.c path_detect.c bot_detect.c ip_reputation.c yara_engine.c ebpf_xdp.c
	$(CC) $(CFLAGS) \
		fw_nfq.c ip_blocklist.c http_inspect.c tcp_monitor.c sqli_detect.c cmdi_detect.c path_detect.c bot_detect.c ip_reputation.c yara_engine.c ebpf_xdp.c \
		-o fw_nfq $(LDFLAGS)

clean:
	rm -f fw_nfq *.o *.ko *.mod *.mod.c .*.cmd modules.order Module.symvers
	rm -rf .tmp_versions
