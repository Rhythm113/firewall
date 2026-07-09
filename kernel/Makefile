obj-m += fw_inspect_mod.o
fw_inspect_mod-y := fw_inspect.o ip_blocklist.o http_inspect.o tcp_monitor.o

# Default targets
all: fw_nfq

# Target for userspace firewall daemon (Docker fallback)
fw_nfq: fw_nfq.c ip_blocklist.c http_inspect.c tcp_monitor.c
	gcc -O2 -Wall -DBUILD_USERSPACE -pthread \
		fw_nfq.c ip_blocklist.c http_inspect.c tcp_monitor.c \
		-o fw_nfq -lnetfilter_queue

# Target for production kernel module compilation
modules:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	rm -f fw_nfq *.o *.ko *.mod *.mod.c .*.cmd modules.order Module.symvers
	rm -rf .tmp_versions
