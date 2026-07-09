#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include "protocol.h"
#include "pgp_wrapper.h"

#define UUID_PATH "/etc/fw_inspect/agent_uuid"
#define BLOCKLIST_PATH "/etc/fw_inspect/blocklist.txt"
#define UNIX_SOCK_PATH "/var/run/fw_inspect.sock"
#define EVENT_BUFFER_SIZE 256

// Global State
static uint8_t agent_uuid[16];
static int soc_fd = -1;
static int fw_fd = -1;
static int is_userspace_mode = 0;
static struct fw_event event_buffer[EVENT_BUFFER_SIZE];
static int event_count = 0;
static volatile sig_atomic_t reload_requested = 0;

// Signal handler for SIGHUP (reload blocklist)
static void handle_sighup(int sig) {
    reload_requested = 1;
}

// Generate random UUID
static void generate_uuid(uint8_t *uuid) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        if (read(fd, uuid, 16) != 16) {
            for (int i = 0; i < 16; i++) uuid[i] = rand() % 256;
        }
        close(fd);
    } else {
        for (int i = 0; i < 16; i++) uuid[i] = rand() % 256;
    }
}

// Load or generate agent UUID
static void load_agent_uuid(void) {
    int fd = open(UUID_PATH, O_RDONLY);
    if (fd >= 0) {
        if (read(fd, agent_uuid, 16) == 16) {
            close(fd);
            printf("[agent] Loaded UUID from %s\n", UUID_PATH);
            return;
        }
        close(fd);
    }

    // Generate new UUID and write it
    generate_uuid(agent_uuid);
    fd = open(UUID_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        if (write(fd, agent_uuid, 16) != 16) {
            perror("[agent] Failed to write generated UUID to file");
        }
        close(fd);
        printf("[agent] Generated and saved new UUID to %s\n", UUID_PATH);
    } else {
        printf("[agent] Generated volatile UUID (failed to save)\n");
    }
}

// Push blocklist payload to firewall
static void push_blocklist_payload(struct blocklist_payload *payload) {
    if (fw_fd < 0) {
        printf("[agent] Firewall not connected. Cannot load blocklist.\n");
        return;
    }

    if (is_userspace_mode) {
        int sent = write(fw_fd, payload, sizeof(struct blocklist_payload));
        if (sent < 0) {
            perror("[agent] Failed to push blocklist to userspace firewall");
        }
    } else {
        struct sockaddr_nl dest_addr;
        memset(&dest_addr, 0, sizeof(dest_addr));
        dest_addr.nl_family = AF_NETLINK;
        dest_addr.nl_pid = 0; // Kernel
        dest_addr.nl_groups = 0;

        struct iovec iov;
        struct nlmsghdr *nlh = malloc(NLMSG_SPACE(sizeof(struct blocklist_payload)));
        memset(nlh, 0, NLMSG_SPACE(sizeof(struct blocklist_payload)));
        nlh->nlmsg_len = NLMSG_SPACE(sizeof(struct blocklist_payload));
        nlh->nlmsg_pid = getpid();
        nlh->nlmsg_flags = 0;
        nlh->nlmsg_type = 2; // LOAD_BLOCKLIST
        memcpy(NLMSG_DATA(nlh), payload, sizeof(struct blocklist_payload));

        iov.iov_base = (void *)nlh;
        iov.iov_len = nlh->nlmsg_len;

        struct msghdr msg;
        memset(&msg, 0, sizeof(msg));
        msg.msg_name = (void *)&dest_addr;
        msg.msg_namelen = sizeof(dest_addr);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

        if (sendmsg(fw_fd, &msg, 0) < 0) {
            perror("[agent] Failed to push blocklist to kernel Netlink socket");
        }
        free(nlh);
    }
}

// Parse and load blocklist from file
static void load_and_push_blocklist(void) {
    printf("[agent] Loading blocklist from %s...\n", BLOCKLIST_PATH);
    FILE *f = fopen(BLOCKLIST_PATH, "r");
    if (!f) {
        perror("[agent] Failed to open blocklist file");
        return;
    }

    struct blocklist_payload payload;
    memset(&payload, 0, sizeof(payload));

    char line[128];
    while (fgets(line, sizeof(line), f) && payload.count < MAX_BLOCKLIST_IPS) {
        char *ip_str = strtok(line, " \t\r\n");
        if (!ip_str || ip_str[0] == '#' || ip_str[0] == '\0') {
            continue;
        }

        char *slash = strchr(ip_str, '/');
        int mask = 32;
        if (slash) {
            *slash = '\0';
            mask = atoi(slash + 1);
        }

        struct in_addr addr;
        if (inet_pton(AF_INET, ip_str, &addr) == 1) {
            payload.entries[payload.count].ip = addr.s_addr;
            payload.entries[payload.count].mask = (uint8_t)mask;
            payload.count++;
        }
    }
    fclose(f);

    printf("[agent] Loaded %d blocklist entries. Pushing to firewall...\n", payload.count);
    push_blocklist_payload(&payload);
}

// Connect to the firewall (tries Netlink, fallbacks to userspace UNIX socket)
static int connect_to_firewall(void) {
    if (fw_fd >= 0) close(fw_fd);

    printf("[agent] Attempting to connect to kernel module via Netlink...\n");
    fw_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_FW_INSPECT);
    if (fw_fd >= 0) {
        struct sockaddr_nl src_addr;
        memset(&src_addr, 0, sizeof(src_addr));
        src_addr.nl_family = AF_NETLINK;
        src_addr.nl_pid = getpid();
        src_addr.nl_groups = 0;

        if (bind(fw_fd, (struct sockaddr *)&src_addr, sizeof(src_addr)) == 0) {
            int register_cmd = 1; // REGISTER_AGENT
            struct sockaddr_nl dest_addr;
            memset(&dest_addr, 0, sizeof(dest_addr));
            dest_addr.nl_family = AF_NETLINK;
            dest_addr.nl_pid = 0; // Kernel
            dest_addr.nl_groups = 0;

            struct nlmsghdr *nlh = malloc(NLMSG_SPACE(sizeof(register_cmd)));
            memset(nlh, 0, NLMSG_SPACE(sizeof(register_cmd)));
            nlh->nlmsg_len = NLMSG_SPACE(sizeof(register_cmd));
            nlh->nlmsg_pid = getpid();
            nlh->nlmsg_flags = 0;
            nlh->nlmsg_type = NLMSG_DONE;
            memcpy(NLMSG_DATA(nlh), &register_cmd, sizeof(register_cmd));

            struct iovec iov;
            iov.iov_base = (void *)nlh;
            iov.iov_len = nlh->nlmsg_len;

            struct msghdr msg;
            memset(&msg, 0, sizeof(msg));
            msg.msg_name = (void *)&dest_addr;
            msg.msg_namelen = sizeof(dest_addr);
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;

            if (sendmsg(fw_fd, &msg, 0) >= 0) {
                printf("[agent] Successfully connected to kernel Netlink socket!\n");
                is_userspace_mode = 0;
                free(nlh);
                return 0;
            }
            free(nlh);
        }
        close(fw_fd);
        fw_fd = -1;
    }

    printf("[agent] Netlink connection failed. Falling back to UNIX socket %s...\n", UNIX_SOCK_PATH);
    fw_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fw_fd >= 0) {
        struct sockaddr_un sa;
        memset(&sa, 0, sizeof(sa));
        sa.sun_family = AF_UNIX;
        strncpy(sa.sun_path, UNIX_SOCK_PATH, sizeof(sa.sun_path) - 1);

        if (connect(fw_fd, (struct sockaddr *)&sa, sizeof(sa)) == 0) {
            printf("[agent] Successfully connected to userspace firewall socket!\n");
            is_userspace_mode = 1;
            return 0;
        }
        close(fw_fd);
        fw_fd = -1;
    }

    fprintf(stderr, "[agent] Failed to connect to any firewall backend. Will retry.\n");
    return -1;
}

// Connect to the SOC server
static int connect_to_soc(void) {
    if (soc_fd >= 0) {
        close(soc_fd);
        soc_fd = -1;
    }

    printf("[agent] Connecting to SOC server at soc-server:%d...\n", SOC_PORT);
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", SOC_PORT);

    int err = getaddrinfo("soc-server", port_str, &hints, &res);
    if (err != 0) {
        fprintf(stderr, "[agent] getaddrinfo failed: %s. Trying localhost fallback...\n", gai_strerror(err));
        err = getaddrinfo("127.0.0.1", port_str, &hints, &res);
        if (err != 0) return -1;
    }

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) {
        freeaddrinfo(res);
        return -1;
    }

    // Set connection timeout (5 seconds)
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(fd, res->ai_addr, res->ai_addrlen) < 0) {
        perror("[agent] Connect to SOC failed");
        close(fd);
        freeaddrinfo(res);
        return -1;
    }

    freeaddrinfo(res);
    soc_fd = fd;
    printf("[agent] Successfully connected to SOC server!\n");
    return 0;
}

// Send payload to SOC server (handles framing + encryption)
static int send_to_soc(uint8_t msg_type, const void *payload_data, size_t payload_len) {
    if (soc_fd < 0) {
        if (connect_to_soc() < 0) {
            return -1;
        }
    }

    char *encrypted_payload = NULL;
    size_t encrypted_len = 0;

    if (payload_len > 0) {
        if (pgp_encrypt(payload_data, payload_len, &encrypted_payload, &encrypted_len) < 0) {
            fprintf(stderr, "[agent] Failed to encrypt payload with PGP\n");
            return -1;
        }
    }

    struct soc_msg_hdr hdr = {
        .magic = htonl(MAGIC_HEADER),
        .msg_type = msg_type,
        .payload_len = htonl((uint32_t)encrypted_len)
    };
    memcpy(hdr.agent_uuid, agent_uuid, 16);

    // Send header
    ssize_t sent = write(soc_fd, &hdr, sizeof(hdr));
    if (sent != sizeof(hdr)) {
        perror("[agent] Failed to write header to SOC");
        if (encrypted_payload) free(encrypted_payload);
        close(soc_fd);
        soc_fd = -1;
        return -1;
    }

    // Send PGP Encrypted payload
    if (encrypted_len > 0 && encrypted_payload) {
        size_t total_sent = 0;
        while (total_sent < encrypted_len) {
            ssize_t bytes_sent = write(soc_fd, encrypted_payload + total_sent, encrypted_len - total_sent);
            if (bytes_sent < 0) {
                perror("[agent] Failed to write PGP payload to SOC");
                free(encrypted_payload);
                close(soc_fd);
                soc_fd = -1;
                return -1;
            }
            total_sent += bytes_sent;
        }
    }

    if (encrypted_payload) free(encrypted_payload);
    printf("[agent] Sent message to SOC (Type: %d, Encrypted size: %zu)\n", msg_type, encrypted_len);
    return 0;
}

// Main execution loop
int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    printf("[agent] Starting Firewall Userspace Agent...\n");
    srand(time(NULL));

    printf("[agent] Initializing PGP keys. Expecting recipient 'soc@soc.local' to be imported in GnuPG keyring.\n");

    load_agent_uuid();
    signal(SIGHUP, handle_sighup);

    connect_to_firewall();
    connect_to_soc();

    load_and_push_blocklist();

    time_t last_flush = time(NULL);
    const int flush_interval = 300;

    unsigned char recv_buf[8192];
    struct sockaddr_nl nl_addr;
    struct iovec iov = {
        .iov_base = recv_buf,
        .iov_len = sizeof(recv_buf)
    };
    struct msghdr msg = {
        .msg_name = &nl_addr,
        .msg_namelen = sizeof(nl_addr),
        .msg_iov = &iov,
        .msg_iovlen = 1
    };

    while (1) {
        if (reload_requested) {
            reload_requested = 0;
            load_and_push_blocklist();
        }

        if (fw_fd < 0) {
            sleep(2);
            connect_to_firewall();
            if (fw_fd >= 0) {
                load_and_push_blocklist();
            }
        }

        fd_set read_fds;
        FD_ZERO(&read_fds);
        int max_fd = -1;

        if (fw_fd >= 0) {
            FD_SET(fw_fd, &read_fds);
            if (fw_fd > max_fd) max_fd = fw_fd;
        }

        if (soc_fd >= 0) {
            FD_SET(soc_fd, &read_fds);
            if (soc_fd > max_fd) max_fd = soc_fd;
        }

        struct timeval timeout;
        time_t now = time(NULL);
        time_t time_to_next_flush = (last_flush + flush_interval) - now;
        if (time_to_next_flush <= 0) {
            time_to_next_flush = 1;
        }
        timeout.tv_sec = time_to_next_flush;
        timeout.tv_usec = 0;

        int ready = select(max_fd + 1, &read_fds, NULL, NULL, &timeout);

        if (ready < 0) {
            if (errno == EINTR) continue;
            perror("[agent] select error");
            sleep(1);
            continue;
        }

        // 1. Process downstream commands from SOC server
        if (soc_fd >= 0 && FD_ISSET(soc_fd, &read_fds)) {
            struct soc_msg_hdr soc_hdr;
            int r = read(soc_fd, &soc_hdr, sizeof(soc_hdr));
            if (r <= 0) {
                printf("[agent] SOC server disconnected. Resetting connection.\n");
                close(soc_fd);
                soc_fd = -1;
                continue;
            }

            if (r == sizeof(soc_hdr) && ntohl(soc_hdr.magic) == MAGIC_HEADER) {
                uint32_t payload_len = ntohl(soc_hdr.payload_len);
                if (payload_len > 0 && payload_len < 16777216) {
                    char *encrypted = malloc(payload_len);
                    if (!encrypted) {
                        fprintf(stderr, "[agent] Failed to allocate memory for payload\n");
                        continue;
                    }
                    size_t total_read = 0;
                    while (total_read < payload_len) {
                        int read_bytes = read(soc_fd, encrypted + total_read, payload_len - total_read);
                        if (read_bytes <= 0) break;
                        total_read += read_bytes;
                    }

                    void *decrypted = NULL;
                    size_t dec_len = 0;
                    if (pgp_decrypt(encrypted, payload_len, &decrypted, &dec_len) == 0) {
                        if (soc_hdr.msg_type == MSG_TYPE_BLOCK_IP) {
                            // Block single IP
                            if (dec_len >= 4) {
                                uint32_t ip = *(uint32_t *)decrypted;
                                char ip_str[32];
                                struct in_addr addr = { .s_addr = ip };
                                inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
                                printf("[agent] Blocking IP: %s\n", ip_str);

                                struct blocklist_payload bl;
                                memset(&bl, 0, sizeof(bl));
                                bl.count = 1;
                                bl.entries[0].ip = ip;
                                bl.entries[0].mask = 32;
                                push_blocklist_payload(&bl);
                            }
                        }
                        else if (soc_hdr.msg_type == MSG_TYPE_YARA_UPDATE) {
                            // Yara rules update
                            printf("[agent] Received YARA update, writing new rules\n");
                            mkdir("/etc/fw_inspect/yara", 0755);
                            FILE *yf = fopen("/etc/fw_inspect/yara/rules.yar", "w");
                            if (yf) {
                                fwrite(decrypted, 1, dec_len, yf);
                                fclose(yf);
                            }
                        }
                        free(decrypted);
                    }
                    free(encrypted);
                }
            }
        }

        // 2. Process events from firewall
        if (fw_fd >= 0 && FD_ISSET(fw_fd, &read_fds)) {
            struct fw_event event;
            int valid_event = 0;

            if (is_userspace_mode) {
                int bytes_read = read(fw_fd, &event, sizeof(struct fw_event));
                if (bytes_read <= 0) {
                    printf("[agent] Userspace firewall disconnected. Resetting socket.\n");
                    close(fw_fd);
                    fw_fd = -1;
                    continue;
                }
                if (bytes_read == sizeof(struct fw_event)) {
                    valid_event = 1;
                }
            } else {
                ssize_t len = recvmsg(fw_fd, &msg, 0);
                if (len < 0) {
                    if (errno == EAGAIN || errno == EINTR) continue;
                    perror("[agent] Netlink recvmsg failed");
                    close(fw_fd);
                    fw_fd = -1;
                    continue;
                }
                struct nlmsghdr *nlh = (struct nlmsghdr *)recv_buf;
                if (NLMSG_OK(nlh, len) && nlh->nlmsg_type == NLMSG_DONE) {
                    memcpy(&event, NLMSG_DATA(nlh), sizeof(struct fw_event));
                    valid_event = 1;
                }
            }

            if (valid_event) {
                printf("[agent] Event received: Type=%d, Severity=%d, Preview='%s'\n",
                       event.threat_type, event.severity, event.payload_preview);

                if (event.severity == SEVERITY_CRITICAL || event.severity == SEVERITY_WARNING) {
                    printf("[agent] Suspicious event detected. Triggering instant alert send...\n");
                    send_to_soc(MSG_TYPE_ALERT, &event, sizeof(struct fw_event));
                } else {
                    if (event_count < EVENT_BUFFER_SIZE) {
                        memcpy(&event_buffer[event_count], &event, sizeof(struct fw_event));
                        event_count++;
                    } else {
                        printf("[agent] Event buffer full. Dropping log.\n");
                    }
                }
            }
        }

        // 3. Heartbeat & Batch timers
        now = time(NULL);
        if (now >= last_flush + flush_interval) {
            printf("[agent] 5-minute timer triggered.\n");
            if (event_count > 0) {
                printf("[agent] Flushing %d batched events to SOC...\n", event_count);
                int ret = send_to_soc(MSG_TYPE_BATCH, event_buffer, event_count * sizeof(struct fw_event));
                if (ret == 0) {
                    event_count = 0;
                }
            } else {
                printf("[agent] No events to report. Sending heartbeat ping to SOC...\n");
                send_to_soc(MSG_TYPE_PING, NULL, 0);
            }
            last_flush = now;
        }
    }

    if (fw_fd >= 0) close(fw_fd);
    if (soc_fd >= 0) close(soc_fd);
    return 0;
}
