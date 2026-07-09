#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "protocol.h"
#include "db.h"
#include "auth.h"
#include "pgp_wrapper.h"
#include "threat_intel.h"

#define MAX_EVENTS 64
#define PORT_AGENT 1113
#define PORT_WEB 8445
#define PORT_LOCAL 8444
#define MAX_SSE_CLIENTS 32
#define BUFFER_SIZE 65536
#define MAX_CONNECTED_AGENTS 128

// Epoll file descriptor
static int epoll_fd = -1;

// List of active SSE client fds for real-time alerts
static int sse_clients[MAX_SSE_CLIENTS];
static pthread_mutex_t sse_mutex = PTHREAD_MUTEX_INITIALIZER;

// Active connected agents registry
struct agent_connection {
    int fd;
    char client_ip[32];
    char buf[BUFFER_SIZE];
    uint32_t bytes_read;
    uint32_t payload_len;
    struct soc_msg_hdr hdr;
    int header_received;
};

static struct agent_connection *connected_agents[MAX_CONNECTED_AGENTS];
static pthread_mutex_t agents_mutex = PTHREAD_MUTEX_INITIALIZER;

// HTTP request parsing connection state
struct http_connection {
    int fd;
    char client_ip[32];
    char buf[8192];
    uint32_t bytes_read;
};

static void sse_init(void) {
    for (int i = 0; i < MAX_SSE_CLIENTS; i++) sse_clients[i] = -1;
}

static void sse_add(int fd) {
    pthread_mutex_lock(&sse_mutex);
    for (int i = 0; i < MAX_SSE_CLIENTS; i++) {
        if (sse_clients[i] == -1) {
            sse_clients[i] = fd;
            break;
        }
    }
    pthread_mutex_unlock(&sse_mutex);
}

static void sse_remove(int fd) {
    pthread_mutex_lock(&sse_mutex);
    for (int i = 0; i < MAX_SSE_CLIENTS; i++) {
        if (sse_clients[i] == fd) {
            sse_clients[i] = -1;
            break;
        }
    }
    pthread_mutex_unlock(&sse_mutex);
}

static void sse_broadcast(const char *event_json) {
    char sse_data[8192];
    int len = snprintf(sse_data, sizeof(sse_data), "data: %s\n\n", event_json);
    if (len < 0) return;

    pthread_mutex_lock(&sse_mutex);
    for (int i = 0; i < MAX_SSE_CLIENTS; i++) {
        int client_fd = sse_clients[i];
        if (client_fd != -1) {
            ssize_t sent = write(client_fd, sse_data, len);
            if (sent < 0) {
                close(client_fd);
                sse_clients[i] = -1;
            }
        }
    }
    pthread_mutex_unlock(&sse_mutex);
}

static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

// Global active agents registry helper functions
static void register_connected_agent(struct agent_connection *conn) {
    pthread_mutex_lock(&agents_mutex);
    for (int i = 0; i < MAX_CONNECTED_AGENTS; i++) {
        if (connected_agents[i] == NULL) {
            connected_agents[i] = conn;
            break;
        }
    }
    pthread_mutex_unlock(&agents_mutex);
}

static void unregister_connected_agent(int fd) {
    pthread_mutex_lock(&agents_mutex);
    for (int i = 0; i < MAX_CONNECTED_AGENTS; i++) {
        if (connected_agents[i] && connected_agents[i]->fd == fd) {
            connected_agents[i] = NULL;
            break;
        }
    }
    pthread_mutex_unlock(&agents_mutex);
}

// Sends block/unblock command down the agent's TCP socket
static int send_command_to_agent(const char *uuid_hex, uint8_t command_type, const void *data, size_t len) {
    uint8_t target_uuid[16];
    // Parse hex UUID to bytes
    for (int i = 0; i < 16; i++) {
        unsigned int val;
        sscanf(uuid_hex + (i * 2), "%02x", &val);
        target_uuid[i] = (uint8_t)val;
    }

    int agent_fd_found = -1;
    pthread_mutex_lock(&agents_mutex);
    for (int i = 0; i < MAX_CONNECTED_AGENTS; i++) {
        if (connected_agents[i] && memcmp(connected_agents[i]->hdr.agent_uuid, target_uuid, 16) == 0) {
            agent_fd_found = connected_agents[i]->fd;
            break;
        }
    }
    pthread_mutex_unlock(&agents_mutex);

    if (agent_fd_found == -1) {
        fprintf(stderr, "[receiver] Agent %s is not currently online\n", uuid_hex);
        return -1;
    }

    char *encrypted = NULL;
    size_t enc_len = 0;
    if (pgp_encrypt(data, len, &encrypted, &enc_len) < 0) {
        fprintf(stderr, "[receiver] Failed to encrypt downstream command with PGP\n");
        return -1;
    }

    struct soc_msg_hdr hdr = {
        .magic = htonl(MAGIC_HEADER),
        .msg_type = command_type,
        .payload_len = htonl((uint32_t)enc_len)
    };
    memcpy(hdr.agent_uuid, target_uuid, 16);

    write(agent_fd_found, &hdr, sizeof(hdr));
    write(agent_fd_found, encrypted, enc_len);
    free(encrypted);

    printf("[receiver] Dispatched command (Type: %d) to agent: %s\n", command_type, uuid_hex);
    return 0;
}

static int create_listen_socket(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    if (listen(fd, 128) < 0) {
        close(fd);
        return -1;
    }

    set_nonblocking(fd);
    return fd;
}

static void send_http_response(int fd, int status_code, const char *status_text, 
                            const char *content_type, const char *extra_headers, 
                            const char *body, size_t body_len) {
    char header_buf[4096];
    int header_len = snprintf(header_buf, sizeof(header_buf),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\n"
        "Access-Control-Allow-Headers: Content-Type, Cookie\r\n"
        "Connection: close\r\n"
        "%s"
        "\r\n",
        status_code, status_text, content_type, body_len, extra_headers ? extra_headers : "");
    
    write(fd, header_buf, header_len);
    if (body && body_len > 0) {
        write(fd, body, body_len);
    }
}

static void serve_static_file(int fd, const char *url_path) {
    char file_path[512];
    if (strstr(url_path, "..")) {
        send_http_response(fd, 403, "Forbidden", "text/plain", NULL, "Access Denied", 13);
        return;
    }

    const char *target_path = url_path;
    if (strcmp(url_path, "/") == 0 || strcmp(url_path, "/index.html") == 0) {
        target_path = "/index.html";
    }

    snprintf(file_path, sizeof(file_path), "/usr/local/share/soc/dashboard%s", target_path);

    int file_fd = open(file_path, O_RDONLY);
    if (file_fd < 0) {
        send_http_response(fd, 404, "Not Found", "text/plain", NULL, "File Not Found", 14);
        return;
    }

    const char *content_type = "text/plain";
    if (strstr(file_path, ".html")) content_type = "text/html";
    else if (strstr(file_path, ".css")) content_type = "text/css";
    else if (strstr(file_path, ".js")) content_type = "application/javascript";
    else if (strstr(file_path, ".png")) content_type = "image/png";
    else if (strstr(file_path, ".svg")) content_type = "image/svg+xml";

    off_t size = lseek(file_fd, 0, SEEK_END);
    lseek(file_fd, 0, SEEK_SET);

    char *body = malloc(size);
    if (body) {
        int bytes_read = read(file_fd, body, size);
        send_http_response(fd, 200, "OK", content_type, NULL, body, bytes_read);
        free(body);
    } else {
        send_http_response(fd, 500, "Internal Error", "text/plain", NULL, "OOM", 3);
    }
    close(file_fd);
}

// Handle REST API requests
static void handle_api_request(int fd, const char *method, const char *path, const char *body, const char *cookie) {
    // CORS Preflight
    if (strcmp(method, "OPTIONS") == 0) {
        send_http_response(fd, 204, "No Content", "text/plain", NULL, NULL, 0);
        return;
    }

    char authenticated_user[128] = {0};
    int auth_ok = -1;

    if (cookie) {
        char *token = strstr(cookie, "session_token=");
        if (token) {
            token += 14;
            char *semicolon = strchr(token, ';');
            char clean_token[512];
            if (semicolon) {
                size_t len = semicolon - token;
                strncpy(clean_token, token, len > 511 ? 511 : len);
                clean_token[len > 511 ? 511 : len] = '\0';
            } else {
                strncpy(clean_token, token, 511);
                clean_token[511] = '\0';
            }
            auth_ok = auth_verify_session_token(clean_token, authenticated_user, sizeof(authenticated_user));
        }
    }

    // Direct Login Route
    if (strcmp(method, "POST") == 0 && strcmp(path, "/auth") == 0) {
        char user[64] = {0}, pass[64] = {0};
        char *u_ptr = strstr(body, "\"username\":\"");
        char *p_ptr = strstr(body, "\"password\":\"");
        if (u_ptr && p_ptr) {
            sscanf(u_ptr, "\"username\":\"%63[^\"]\"", user);
            sscanf(p_ptr, "\"password\":\"%63[^\"]\"", pass);
        }

        if (strlen(user) > 0 && strlen(pass) > 0 && auth_verify_login(user, pass) == 0) {
            char session_token[512];
            auth_generate_session_token(user, session_token, sizeof(session_token));

            char cookie_header[1024];
            snprintf(cookie_header, sizeof(cookie_header), 
                "Set-Cookie: session_token=%s; Path=/; HttpOnly; SameSite=Strict; Max-Age=28800\r\n", 
                session_token);

            send_http_response(fd, 200, "OK", "application/json", cookie_header, "{\"status\":\"success\"}", 20);
        } else {
            send_http_response(fd, 401, "Unauthorized", "application/json", NULL, "{\"status\":\"failed\"}", 19);
        }
        return;
    }

    if (auth_ok != 0) {
        if (strncmp(path, "/api/events/live", 16) == 0) {
            // Checked inside live handler
        } else {
            send_http_response(fd, 401, "Unauthorized", "application/json", NULL, "{\"error\":\"unauthenticated\"}", 27);
            return;
        }
    }

    // --- V2 API Routing ---

    // Stats
    if (strcmp(method, "GET") == 0 && (strcmp(path, "/api/stats") == 0 || strcmp(path, "/api/v2/dashboard/stats") == 0)) {
        char *json = db_get_stats_json();
        send_http_response(fd, 200, "OK", "application/json", NULL, json, strlen(json));
        free(json);
    }
    // Agents list
    else if (strcmp(method, "GET") == 0 && (strcmp(path, "/api/agents") == 0 || strcmp(path, "/api/v2/agents") == 0)) {
        char *json = db_get_agents_json();
        send_http_response(fd, 200, "OK", "application/json", NULL, json, strlen(json));
        free(json);
    }
    // Remove Agent
    else if (strcmp(method, "DELETE") == 0 && strncmp(path, "/api/v2/agents/", 15) == 0) {
        char uuid_str[64] = {0};
        sscanf(path, "/api/v2/agents/%63s", uuid_str);
        // Convert format to standard UUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
        uint8_t target_uuid[16];
        int parse_ok = 1;
        for (int i = 0; i < 16; i++) {
            unsigned int val;
            char hex_part[3] = { uuid_str[i*2], uuid_str[i*2+1], '\0' };
            if (sscanf(hex_part, "%2x", &val) != 1) {
                parse_ok = 0; break;
            }
            target_uuid[i] = (uint8_t)val;
        }
        if (parse_ok && db_remove_agent(target_uuid) == 0) {
            send_http_response(fd, 200, "OK", "application/json", NULL, "{\"status\":\"removed\"}", 20);
        } else {
            send_http_response(fd, 400, "Bad Request", "application/json", NULL, "{\"error\":\"invalid_uuid\"}", 24);
        }
    }
    // Block IP Command to Agent
    else if (strcmp(method, "POST") == 0 && strncmp(path, "/api/v2/agents/", 15) == 0 && strstr(path, "/block-ip")) {
        char uuid_str[64] = {0};
        sscanf(path, "/api/v2/agents/%63[^/]", uuid_str);
        
        char ip_to_block[64] = {0};
        char *ip_ptr = strstr(body, "\"ip\":\"");
        if (ip_ptr) {
            sscanf(ip_ptr, "\"ip\":\"%63[^\"]\"", ip_to_block);
        }

        struct in_addr addr;
        if (strlen(ip_to_block) > 0 && inet_pton(AF_INET, ip_to_block, &addr) == 1) {
            // Push to db blocklist
            db_add_to_blocklist(ip_to_block, "block", "Dashboard manual block");

            // Push downstream to active agent
            uint32_t net_ip = addr.s_addr;
            if (send_command_to_agent(uuid_str, MSG_TYPE_BLOCK_IP, &net_ip, sizeof(net_ip)) == 0) {
                send_http_response(fd, 200, "OK", "application/json", NULL, "{\"status\":\"blocked\"}", 20);
            } else {
                send_http_response(fd, 404, "Not Found", "application/json", NULL, "{\"error\":\"agent_offline\"}", 25);
            }
        } else {
            send_http_response(fd, 400, "Bad Request", "application/json", NULL, "{\"error\":\"invalid_ip\"}", 22);
        }
    }
    // Get Blocklist
    else if (strcmp(method, "GET") == 0 && strcmp(path, "/api/v2/blocklist") == 0) {
        char *json = db_get_blocklist_json("block");
        send_http_response(fd, 200, "OK", "application/json", NULL, json, strlen(json));
        free(json);
    }
    // Add to Blocklist
    else if (strcmp(method, "POST") == 0 && strcmp(path, "/api/v2/blocklist") == 0) {
        char ip_cidr[64] = {0}, reason[128] = {0};
        char *ip_ptr = strstr(body, "\"ip_cidr\":\"");
        char *reason_ptr = strstr(body, "\"reason\":\"");
        if (ip_ptr) sscanf(ip_ptr, "\"ip_cidr\":\"%63[^\"]\"", ip_cidr);
        if (reason_ptr) sscanf(reason_ptr, "\"reason\":\"%127[^\"]\"", reason);

        if (strlen(ip_cidr) > 0 && db_add_to_blocklist(ip_cidr, "block", reason) == 0) {
            send_http_response(fd, 200, "OK", "application/json", NULL, "{\"status\":\"added\"}", 18);
        } else {
            send_http_response(fd, 400, "Bad Request", "application/json", NULL, "{\"error\":\"invalid_input\"}", 25);
        }
    }
    // Delete from Blocklist
    else if (strcmp(method, "DELETE") == 0 && strncmp(path, "/api/v2/blocklist/", 18) == 0) {
        char ip_cidr[64] = {0};
        sscanf(path, "/api/v2/blocklist/%63s", ip_cidr);
        if (strlen(ip_cidr) > 0 && db_remove_from_blocklist(ip_cidr, "block") == 0) {
            send_http_response(fd, 200, "OK", "application/json", NULL, "{\"status\":\"removed\"}", 20);
        } else {
            send_http_response(fd, 400, "Bad Request", "application/json", NULL, "{\"error\":\"invalid_input\"}", 25);
        }
    }
    // Get IP Reputation
    else if (strcmp(method, "GET") == 0 && strcmp(path, "/api/v2/reputation") == 0) {
        char *json = db_get_reputation_json(NULL);
        send_http_response(fd, 200, "OK", "application/json", NULL, json, strlen(json));
        free(json);
    }
    // Get YARA rules
    else if (strcmp(method, "GET") == 0 && strcmp(path, "/api/v2/yara/rules") == 0) {
        char *json = db_get_yara_rules_json();
        send_http_response(fd, 200, "OK", "application/json", NULL, json, strlen(json));
        free(json);
    }
    // Upload YARA rules
    else if (strcmp(method, "POST") == 0 && strcmp(path, "/api/v2/yara/rules") == 0) {
        char name[128] = {0}, content[4096] = {0};
        char *name_ptr = strstr(body, "\"name\":\"");
        char *content_ptr = strstr(body, "\"content\":\"");
        if (name_ptr) sscanf(name_ptr, "\"name\":\"%127[^\"]\"", name);
        if (content_ptr) sscanf(content_ptr, "\"content\":\"%4095[^\"]\"", content);

        if (strlen(name) > 0 && db_add_yara_rule(name, content) == 0) {
            send_http_response(fd, 200, "OK", "application/json", NULL, "{\"status\":\"added\"}", 18);
        } else {
            send_http_response(fd, 400, "Bad Request", "application/json", NULL, "{\"error\":\"invalid_input\"}", 25);
        }
    }
    // Delete YARA rules
    else if (strcmp(method, "DELETE") == 0 && strncmp(path, "/api/v2/yara/rules/", 19) == 0) {
        char name[128] = {0};
        sscanf(path, "/api/v2/yara/rules/%127s", name);
        if (strlen(name) > 0 && db_delete_yara_rule(name) == 0) {
            send_http_response(fd, 200, "OK", "application/json", NULL, "{\"status\":\"removed\"}", 20);
        } else {
            send_http_response(fd, 400, "Bad Request", "application/json", NULL, "{\"error\":\"invalid_input\"}", 25);
        }
    }
    // Get Configs
    else if (strcmp(method, "GET") == 0 && strcmp(path, "/api/v2/config") == 0) {
        char *json = db_get_config_json();
        send_http_response(fd, 200, "OK", "application/json", NULL, json, strlen(json));
        free(json);
    }
    // Set Config
    else if (strcmp(method, "POST") == 0 && strcmp(path, "/api/v2/config") == 0) {
        char key[64] = {0}, val[256] = {0}, cat[64] = {0};
        char *key_ptr = strstr(body, "\"key\":\"");
        char *val_ptr = strstr(body, "\"value\":");
        char *cat_ptr = strstr(body, "\"category\":\"");
        if (key_ptr) sscanf(key_ptr, "\"key\":\"%63[^\"]\"", key);
        if (cat_ptr) sscanf(cat_ptr, "\"category\":\"%63[^\"]\"", cat);

        if (val_ptr) {
            val_ptr += 8;
            int len = 0;
            while (val_ptr[len] != '\0' && val_ptr[len] != '}' && val_ptr[len] != ',') {
                len++;
            }
            strncpy(val, val_ptr, len > 255 ? 255 : len);
            val[len > 255 ? 255 : len] = '\0';
        }

        if (strlen(key) > 0 && db_set_config(key, val, cat, "Updated via dashboard") == 0) {
            send_http_response(fd, 200, "OK", "application/json", NULL, "{\"status\":\"saved\"}", 18);
        } else {
            send_http_response(fd, 400, "Bad Request", "application/json", NULL, "{\"error\":\"invalid_input\"}", 25);
        }
    }
    // Get Threat Intel
    else if (strcmp(method, "GET") == 0 && strcmp(path, "/api/v2/threat-intel") == 0) {
        char *json = db_get_threat_intel_json();
        send_http_response(fd, 200, "OK", "application/json", NULL, json, strlen(json));
        free(json);
    }
    // Manual Threat Intel Aggregation Trigger
    else if (strcmp(method, "POST") == 0 && strcmp(path, "/api/v2/threat-intel/fetch") == 0) {
        trigger_feed_fetch();
        send_http_response(fd, 200, "OK", "application/json", NULL, "{\"status\":\"fetching\"}", 21);
    }
    // Events list
    else if (strcmp(method, "GET") == 0 && strncmp(path, "/api/events", 11) == 0 && strncmp(path, "/api/events/live", 16) != 0) {
        int limit = 50;
        int offset = 0;
        char agent_filter[64] = {0};

        char *limit_ptr = strstr(path, "limit=");
        if (limit_ptr) limit = atoi(limit_ptr + 6);

        char *offset_ptr = strstr(path, "offset=");
        if (offset_ptr) offset = atoi(offset_ptr + 7);

        char *agent_ptr = strstr(path, "agent=");
        if (agent_ptr) sscanf(agent_ptr, "agent=%63s", agent_filter);

        char *json = db_get_events_json(limit, offset, strlen(agent_filter) > 0 ? agent_filter : NULL);
        send_http_response(fd, 200, "OK", "application/json", NULL, json, strlen(json));
        free(json);
    }
    // Server-Sent Events handshake
    else if (strcmp(method, "GET") == 0 && strncmp(path, "/api/events/live", 16) == 0) {
        if (auth_ok != 0) {
            char *token_param = strstr(path, "token=");
            if (token_param) {
                char clean_token[512];
                sscanf(token_param, "token=%511s", clean_token);
                auth_ok = auth_verify_session_token(clean_token, authenticated_user, sizeof(authenticated_user));
            }
        }

        if (auth_ok != 0) {
            send_http_response(fd, 401, "Unauthorized", "text/plain", NULL, "Unauthorized", 12);
            return;
        }

        char response_headers[] = 
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/event-stream\r\n"
            "Cache-Control: no-cache\r\n"
            "Connection: keep-alive\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "\r\n";
        
        write(fd, response_headers, strlen(response_headers));
        sse_add(fd);
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL);
    }
    else {
        send_http_response(fd, 404, "Not Found", "application/json", NULL, "{\"error\":\"not_found\"}", 22);
    }
}

// Process messages from agents
static void process_agent_message(struct agent_connection *conn) {
    void *decrypted_payload = NULL;
    size_t decrypted_len = 0;

    printf("[receiver] Processing message from agent %s (Type: %d, Len: %d)\n", 
           conn->client_ip, conn->hdr.msg_type, conn->payload_len);

    db_update_agent_last_seen(conn->hdr.agent_uuid, conn->client_ip);

    if (conn->payload_len > 0) {
        if (pgp_decrypt(conn->buf, conn->payload_len, &decrypted_payload, &decrypted_len) < 0) {
            fprintf(stderr, "[receiver] Failed to decrypt agent PGP payload\n");
            return;
        }

        if (conn->hdr.msg_type == MSG_TYPE_ALERT) {
            if (decrypted_len == sizeof(struct fw_event)) {
                struct fw_event *event = (struct fw_event *)decrypted_payload;
                db_insert_event(conn->hdr.agent_uuid, event);

                char agent_hex[33];
                for (int i = 0; i < 16; i++) sprintf(agent_hex + (i * 2), "%02x", conn->hdr.agent_uuid[i]);
                agent_hex[32] = '\0';

                char src_ip_str[32], dest_ip_str[32];
                struct in_addr addr;
                addr.s_addr = event->src_ip; inet_ntop(AF_INET, &addr, src_ip_str, 32);
                addr.s_addr = event->dest_ip; inet_ntop(AF_INET, &addr, dest_ip_str, 32);

                char json_alert[2048];
                snprintf(json_alert, sizeof(json_alert),
                    "{\"agent_uuid\":\"%s\",\"timestamp\":%lld,\"src_ip\":\"%s\",\"dest_ip\":\"%s\","
                    "\"src_port\":%d,\"dest_port\":%d,\"threat_type\":%d,\"severity\":%d,"
                    "\"payload_preview\":\"%s\",\"details\":\"%s\"}",
                    agent_hex, (long long)event->timestamp, src_ip_str, dest_ip_str,
                    ntohs(event->src_port), ntohs(event->dest_port), event->threat_type, event->severity,
                    event->payload_preview, event->details);

                sse_broadcast(json_alert);
            }
        } 
        else if (conn->hdr.msg_type == MSG_TYPE_BATCH) {
            int num_events = decrypted_len / sizeof(struct fw_event);
            struct fw_event *events = (struct fw_event *)decrypted_payload;
            printf("[receiver] Batch contains %d events. Inserting to database...\n", num_events);

            for (int i = 0; i < num_events; i++) {
                db_insert_event(conn->hdr.agent_uuid, &events[i]);
            }
        }

        if (decrypted_payload) free(decrypted_payload);
    } else {
        printf("[receiver] Received idle heartbeat ping from agent %s\n", conn->client_ip);
    }
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    printf("[receiver] Starting Custom SOC Receiver Daemon...\n");

    // Initialize database with a retry loop for startup synchronization
    int db_connected = 0;
    for (int retries = 15; retries > 0; retries--) {
        if (db_init(NULL) == 0) {
            db_connected = 1;
            break;
        }
        printf("[receiver] Database not ready yet, retrying in 2 seconds (%d retries remaining)...\n", retries - 1);
        sleep(2);
    }

    if (!db_connected) {
        fprintf(stderr, "[receiver] Failed to initialize PostgreSQL connection after multiple attempts.\n");
        return 1;
    }

    auth_init();
    sse_init();
    init_threat_intel();

    memset(connected_agents, 0, sizeof(connected_agents));

    int listen_agent_fd = create_listen_socket(PORT_AGENT);
    int listen_web_fd = create_listen_socket(PORT_WEB);
    int listen_local_fd = create_listen_socket(PORT_LOCAL);

    if (listen_agent_fd < 0 || listen_web_fd < 0 || listen_local_fd < 0) {
        fprintf(stderr, "[receiver] Failed to bind listening sockets\n");
        cleanup_threat_intel();
        db_close();
        if (listen_agent_fd >= 0) close(listen_agent_fd);
        if (listen_web_fd >= 0) close(listen_web_fd);
        if (listen_local_fd >= 0) close(listen_local_fd);
        return 1;
    }

    printf("[receiver] Listening for Agent connections on port %d...\n", PORT_AGENT);
    printf("[receiver] Listening for Web/Dashboard connections on port %d...\n", PORT_WEB);
    printf("[receiver] Listening for Local Controller connections on port %d...\n", PORT_LOCAL);

    epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        perror("[receiver] epoll_create failed");
        cleanup_threat_intel();
        db_close();
        close(listen_agent_fd);
        close(listen_web_fd);
        close(listen_local_fd);
        return 1;
    }

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = listen_agent_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_agent_fd, &ev);

    ev.events = EPOLLIN;
    ev.data.fd = listen_web_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_web_fd, &ev);

    ev.events = EPOLLIN;
    ev.data.fd = listen_local_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_local_fd, &ev);

    struct epoll_event events[MAX_EVENTS];

    while (1) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        if (nfds < 0) {
            if (errno == EINTR) continue;
            perror("[receiver] epoll_wait failed");
            break;
        }

        for (int i = 0; i < nfds; i++) {
            int fd = events[i].data.fd;

            if (fd == listen_agent_fd) {
                struct sockaddr_in client_addr;
                socklen_t client_len = sizeof(client_addr);
                int client_fd = accept(listen_agent_fd, (struct sockaddr *)&client_addr, &client_len);
                if (client_fd < 0) continue;

                char client_ip[32];
                inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));

                if (!auth_check_ip(client_ip)) {
                    printf("[receiver] Blocked agent connection from non-whitelisted IP: %s\n", client_ip);
                    close(client_fd);
                    continue;
                }

                printf("[receiver] Accepted agent connection from %s\n", client_ip);
                set_nonblocking(client_fd);

                struct agent_connection *conn = calloc(1, sizeof(struct agent_connection));
                conn->fd = client_fd;
                strcpy(conn->client_ip, client_ip);

                register_connected_agent(conn);

                ev.events = EPOLLIN | EPOLLRDHUP;
                ev.data.ptr = conn;
                epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &ev);
            }
            else if (fd == listen_local_fd) {
                struct sockaddr_in client_addr;
                socklen_t client_len = sizeof(client_addr);
                int client_fd = accept(listen_local_fd, (struct sockaddr *)&client_addr, &client_len);
                if (client_fd >= 0) {
                    struct local_cmd {
                        char agent_uuid_hex[33];
                        uint8_t command_type;
                        uint32_t ip;
                    } cmd;
                    
                    int bytes = read(client_fd, &cmd, sizeof(cmd));
                    if (bytes == sizeof(cmd)) {
                        cmd.agent_uuid_hex[32] = '\0';
                        printf("[receiver] Received local control command: Block IP %u for Agent %s\n", cmd.ip, cmd.agent_uuid_hex);
                        send_command_to_agent(cmd.agent_uuid_hex, cmd.command_type, &cmd.ip, sizeof(cmd.ip));
                    }
                    close(client_fd);
                }
            }
            else if (fd == listen_web_fd) {
                struct sockaddr_in client_addr;
                socklen_t client_len = sizeof(client_addr);
                int client_fd = accept(listen_web_fd, (struct sockaddr *)&client_addr, &client_len);
                if (client_fd < 0) continue;

                char client_ip[32];
                inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));

                if (!auth_check_ip(client_ip)) {
                    printf("[receiver] Blocked web connection from non-whitelisted IP: %s\n", client_ip);
                    close(client_fd);
                    continue;
                }

                set_nonblocking(client_fd);

                struct http_connection *conn = calloc(1, sizeof(struct http_connection));
                conn->fd = client_fd;
                strcpy(conn->client_ip, client_ip);

                ev.events = EPOLLIN | EPOLLRDHUP;
                ev.data.ptr = conn;
                epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &ev);
            } 
            else {
                uint32_t epoll_events = events[i].events;

                if (epoll_events & (EPOLLRDHUP | EPOLLHUP | EPOLLERR)) {
                    void *ptr = events[i].data.ptr;
                    int *client_fd_ptr = (int *)ptr;
                    if (client_fd_ptr) {
                        int client_fd = *client_fd_ptr;
                        printf("[receiver] Connection closed on fd %d\n", client_fd);
                        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, client_fd, NULL);
                        unregister_connected_agent(client_fd);
                        close(client_fd);
                        sse_remove(client_fd);
                        free(ptr);
                    }
                    continue;
                }

                struct generic_conn {
                    int fd;
                    int type; 
                } *g_conn = (struct generic_conn *)events[i].data.ptr;

                if (!g_conn) continue;

                struct sockaddr_in local_addr;
                socklen_t addr_len = sizeof(local_addr);
                getsockname(g_conn->fd, (struct sockaddr *)&local_addr, &addr_len);
                int local_port = ntohs(local_addr.sin_port);

                if (local_port == PORT_AGENT) {
                    struct agent_connection *conn = (struct agent_connection *)events[i].data.ptr;
                    
                    if (!conn->header_received) {
                        int needed = sizeof(struct soc_msg_hdr) - conn->bytes_read;
                        int r = read(conn->fd, ((char *)&conn->hdr) + conn->bytes_read, needed);
                        if (r <= 0) {
                            if (r < 0 && errno == EAGAIN) continue;
                            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, conn->fd, NULL);
                            unregister_connected_agent(conn->fd);
                            close(conn->fd);
                            free(conn);
                            continue;
                        }
                        conn->bytes_read += r;
                        if (conn->bytes_read == sizeof(struct soc_msg_hdr)) {
                            conn->header_received = 1;
                            conn->payload_len = ntohl(conn->hdr.payload_len);
                            conn->bytes_read = 0;
                            
                            if (ntohl(conn->hdr.magic) != MAGIC_HEADER) {
                                fprintf(stderr, "[receiver] Invalid header magic. Disconnecting.\n");
                                epoll_ctl(epoll_fd, EPOLL_CTL_DEL, conn->fd, NULL);
                                unregister_connected_agent(conn->fd);
                                close(conn->fd);
                                free(conn);
                                continue;
                            }

                            if (conn->payload_len >= BUFFER_SIZE) {
                                fprintf(stderr, "[receiver] Payload too large (%u). Disconnecting.\n", conn->payload_len);
                                epoll_ctl(epoll_fd, EPOLL_CTL_DEL, conn->fd, NULL);
                                unregister_connected_agent(conn->fd);
                                close(conn->fd);
                                free(conn);
                                continue;
                            }
                        }
                    }

                    if (conn->header_received) {
                        if (conn->payload_len == 0) {
                            process_agent_message(conn);
                            conn->header_received = 0;
                            conn->bytes_read = 0;
                        } else {
                            uint32_t needed = conn->payload_len - conn->bytes_read;
                            int r = read(conn->fd, conn->buf + conn->bytes_read, needed);
                            if (r <= 0) {
                                if (r < 0 && errno == EAGAIN) continue;
                                epoll_ctl(epoll_fd, EPOLL_CTL_DEL, conn->fd, NULL);
                                unregister_connected_agent(conn->fd);
                                close(conn->fd);
                                free(conn);
                                continue;
                            }
                            conn->bytes_read += r;
                            if (conn->bytes_read == conn->payload_len) {
                                process_agent_message(conn);
                                conn->header_received = 0;
                                conn->bytes_read = 0;
                            }
                        }
                    }
                } 
                else if (local_port == PORT_WEB) {
                    struct http_connection *conn = (struct http_connection *)events[i].data.ptr;
                    int r = read(conn->fd, conn->buf + conn->bytes_read, sizeof(conn->buf) - conn->bytes_read - 1);
                    if (r <= 0) {
                        if (r < 0 && errno == EAGAIN) continue;
                        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, conn->fd, NULL);
                        close(conn->fd);
                        free(conn);
                        continue;
                    }
                    conn->bytes_read += r;
                    conn->buf[conn->bytes_read] = '\0';

                    char *end_headers = strstr(conn->buf, "\r\n\r\n");
                    if (end_headers) {
                        char method[16] = {0}, path[512] = {0};
                        sscanf(conn->buf, "%15s %511s", method, path);

                        char *cookie_header = strcasestr(conn->buf, "Cookie:");
                        char cookie_val[512] = {0};
                        if (cookie_header) {
                            sscanf(cookie_header, "Cookie: %511[^\r\n]", cookie_val);
                        }

                        char *cl_header = strcasestr(conn->buf, "Content-Length:");
                        int content_length = 0;
                        if (cl_header) {
                            content_length = atoi(cl_header + 15);
                        }

                        char *body_start = end_headers + 4;
                        int body_read = conn->bytes_read - (body_start - conn->buf);

                        if (strcmp(method, "POST") == 0 && body_read < content_length) {
                            continue;
                        }

                        if (strncmp(path, "/api/", 5) == 0 || strcmp(path, "/auth") == 0) {
                            handle_api_request(conn->fd, method, path, body_start, strlen(cookie_val) > 0 ? cookie_val : NULL);
                        } else {
                            serve_static_file(conn->fd, path);
                        }

                        if (strcmp(path, "/api/events/live") != 0) {
                            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, conn->fd, NULL);
                            close(conn->fd);
                            free(conn);
                        }
                    }
                }
            }
        }
    }

    cleanup_threat_intel();
    db_close();
    close(listen_agent_fd);
    close(listen_web_fd);
    close(listen_local_fd);
    return 0;
}
