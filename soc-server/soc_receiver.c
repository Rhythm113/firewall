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

#define MAX_EVENTS 64
#define PORT_AGENT 1113
#define PORT_WEB 8443
#define MAX_SSE_CLIENTS 32
#define BUFFER_SIZE 65536

// Epoll file descriptor
static int epoll_fd = -1;

// List of active SSE client fds for real-time alerts
static int sse_clients[MAX_SSE_CLIENTS];
static pthread_mutex_t sse_mutex = PTHREAD_MUTEX_INITIALIZER;

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
            // Write to socket; if write fails, disconnect the client
            ssize_t sent = write(client_fd, sse_data, len);
            if (sent < 0) {
                close(client_fd);
                sse_clients[i] = -1;
            }
        }
    }
    pthread_mutex_unlock(&sse_mutex);
}

// Utility to set non-blocking
static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

// Structures to keep track of partial reads on agent connections
struct agent_connection {
    int fd;
    char client_ip[32];
    char buf[BUFFER_SIZE];
    int bytes_read;
    int payload_len;
    struct soc_msg_hdr hdr;
    int header_received;
};

// Structures to keep track of HTTP request parsing
struct http_connection {
    int fd;
    char client_ip[32];
    char buf[8192];
    int bytes_read;
};

// Create a listening TCP socket
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

// Send HTTP responses
static void send_http_response(int fd, int status_code, const char *status_text, 
                            const char *content_type, const char *extra_headers, 
                            const char *body, size_t body_len) {
    char header_buf[4096];
    int header_len = snprintf(header_buf, sizeof(header_buf),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "%s"
        "\r\n",
        status_code, status_text, content_type, body_len, extra_headers ? extra_headers : "");
    
    // Write header
    write(fd, header_buf, header_len);
    // Write body
    if (body && body_len > 0) {
        write(fd, body, body_len);
    }
}

// Serves static files
static void serve_static_file(int fd, const char *url_path) {
    char file_path[512];
    // Sanitize path to prevent directory traversal
    if (strstr(url_path, "..")) {
        send_http_response(fd, 403, "Forbidden", "text/plain", NULL, "Access Denied", 13);
        return;
    }

    // Default route
    if (strcmp(url_path, "/") == 0 || strcmp(url_path, "/index.html") == 0) {
        strcpy(url_path, "/index.html");
    }

    snprintf(file_path, sizeof(file_path), "/usr/local/share/soc/dashboard%s", url_path);

    int file_fd = open(file_path, O_RDONLY);
    if (file_fd < 0) {
        // Fallback for SPA routing or 404
        send_http_response(fd, 404, "Not Found", "text/plain", NULL, "File Not Found", 14);
        return;
    }

    // Determine content type
    const char *content_type = "text/plain";
    if (strstr(file_path, ".html")) content_type = "text/html";
    else if (strstr(file_path, ".css")) content_type = "text/css";
    else if (strstr(file_path, ".js")) content_type = "application/javascript";
    else if (strstr(file_path, ".png")) content_type = "image/png";
    else if (strstr(file_path, ".svg")) content_type = "image/svg+xml";

    // Read file size
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
    // 1. Authenticate check for all /api endpoints except /api/events/live (which needs URL param or cookie)
    char authenticated_user[128] = {0};
    int auth_ok = -1;

    if (cookie) {
        char *token = strstr(cookie, "session_token=");
        if (token) {
            token += 14; // length of "session_token="
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
        // Parse simple Form or JSON fields
        char user[64] = {0}, pass[64] = {0};
        // Simple extraction: expecting JSON {"username":"admin","password":"password"}
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

    // Enforce authentication for API routes
    if (auth_ok != 0) {
        // SSE has a fallback: token in URL query parameter
        if (strncmp(path, "/api/events/live", 16) == 0) {
            // We bypass or let it proceed if we can extract token from query param (will handle below)
        } else {
            send_http_response(fd, 401, "Unauthorized", "application/json", NULL, "{\"error\":\"unauthenticated\"}", 27);
            return;
        }
    }

    // Get Event stats
    if (strcmp(method, "GET") == 0 && strcmp(path, "/api/stats") == 0) {
        char *json = db_get_stats_json();
        if (json) {
            send_http_response(fd, 200, "OK", "application/json", NULL, json, strlen(json));
            free(json);
        } else {
            send_http_response(fd, 500, "Internal Error", "application/json", NULL, "{}", 2);
        }
    }
    // Get Agents list
    else if (strcmp(method, "GET") == 0 && strcmp(path, "/api/agents") == 0) {
        char *json = db_get_agents_json();
        if (json) {
            send_http_response(fd, 200, "OK", "application/json", NULL, json, strlen(json));
            free(json);
        } else {
            send_http_response(fd, 500, "Internal Error", "application/json", NULL, "[]", 2);
        }
    }
    // Get Events history
    else if (strcmp(method, "GET") == 0 && strncmp(path, "/api/events", 11) == 0 && strncmp(path, "/api/events/live", 16) != 0) {
        // Parse limit/offset/agent filter if any (very simplified query parsing)
        int limit = 50;
        int offset = 0;
        char agent_filter[64] = {0};

        char *limit_ptr = strstr(path, "limit=");
        if (limit_ptr) limit = atoi(limit_ptr + 6);

        char *offset_ptr = strstr(path, "offset=");
        if (offset_ptr) offset = atoi(offset_ptr + 7);

        char *agent_ptr = strstr(path, "agent=");
        if (agent_ptr) sscanf(agent_ptr, "agent=%32s", agent_filter);

        char *json = db_get_events_json(limit, offset, strlen(agent_filter) > 0 ? agent_filter : NULL);
        if (json) {
            send_http_response(fd, 200, "OK", "application/json", NULL, json, strlen(json));
            free(json);
        } else {
            send_http_response(fd, 500, "Internal Error", "application/json", NULL, "[]", 2);
        }
    }
    // Real-time events stream (Server-Sent Events)
    else if (strcmp(method, "GET") == 0 && strncmp(path, "/api/events/live", 16) == 0) {
        // SSE connection handshake
        // If not authenticated via cookie, check if token is in URL (e.g. ?token=...)
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

        // Send headers for SSE
        char response_headers[] = 
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/event-stream\r\n"
            "Cache-Control: no-cache\r\n"
            "Connection: keep-alive\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "\r\n";
        
        write(fd, response_headers, strlen(response_headers));
        
        // Put socket into non-blocking, but do not remove from epoll.
        // Instead, add to SSE broadcast client list so receiver can send live events.
        sse_add(fd);
        
        // Remove write/read tracking in epoll main loop so it stays open for broadcast
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL);
    }
    else {
        send_http_response(fd, 404, "Not Found", "application/json", NULL, "{\"error\":\"not_found\"}", 22);
    }
}

// Handle Agent data messages
static void process_agent_message(struct agent_connection *conn) {
    void *decrypted_payload = NULL;
    size_t decrypted_len = 0;

    printf("[receiver] Processing message from agent %s (Type: %d, Len: %d)\n", 
           conn->client_ip, conn->hdr.msg_type, conn->payload_len);

    // Update agent's last seen in database
    db_update_agent_last_seen(conn->hdr.agent_uuid, conn->client_ip);

    if (conn->payload_len > 0) {
        // PGP Decrypt payload
        if (pgp_decrypt(conn->buf, conn->payload_len, &decrypted_payload, &decrypted_len) < 0) {
            fprintf(stderr, "[receiver] Failed to decrypt agent PGP payload\n");
            return;
        }

        // Handle decoded payload based on message type
        if (conn->hdr.msg_type == MSG_TYPE_ALERT) {
            // Alert mode: payload contains exactly one struct fw_event
            if (decrypted_len == sizeof(struct fw_event)) {
                struct fw_event *event = (struct fw_event *)decrypted_payload;
                db_insert_event(conn->hdr.agent_uuid, event);

                // Broadcast real-time alert via SSE
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
            // Batch mode: payload contains N event records
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

    // Initialize database
    if (db_init("/var/lib/soc/soc.db") != 0) {
        fprintf(stderr, "[receiver] Failed to initialize database\n");
        return 1;
    }

    // Initialize whitelist and session configurations
    auth_init();
    sse_init();

    // Create listen sockets
    int listen_agent_fd = create_listen_socket(PORT_AGENT);
    int listen_web_fd = create_listen_socket(PORT_WEB);

    if (listen_agent_fd < 0 || listen_web_fd < 0) {
        fprintf(stderr, "[receiver] Failed to bind listening sockets\n");
        db_close();
        return 1;
    }

    printf("[receiver] Listening for Agent connections on port %d...\n", PORT_AGENT);
    printf("[receiver] Listening for Web/Dashboard connections on port %d...\n", PORT_WEB);

    // Create epoll
    epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        perror("[receiver] epoll_create failed");
        return 1;
    }

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = listen_agent_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_agent_fd, &ev);

    ev.events = EPOLLIN;
    ev.data.fd = listen_web_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_web_fd, &ev);

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
                // Incoming agent connection
                struct sockaddr_in client_addr;
                socklen_t client_len = sizeof(client_addr);
                int client_fd = accept(listen_agent_fd, (struct sockaddr *)&client_addr, &client_len);
                if (client_fd < 0) continue;

                char client_ip[32];
                inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));

                // ENFORCE WHITELIST
                if (!auth_check_ip(client_ip)) {
                    printf("[receiver] Blocked agent connection from non-whitelisted IP: %s\n", client_ip);
                    close(client_fd);
                    continue;
                }

                printf("[receiver] Accepted agent connection from %s\n", client_ip);
                set_nonblocking(client_fd);

                // Allocate client session state
                struct agent_connection *conn = calloc(1, sizeof(struct agent_connection));
                conn->fd = client_fd;
                strcpy(conn->client_ip, client_ip);

                ev.events = EPOLLIN | EPOLLRDHUP;
                ev.data.ptr = conn; // Track connection state struct
                epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &ev);
            } 
            else if (fd == listen_web_fd) {
                // Incoming web connection
                struct sockaddr_in client_addr;
                socklen_t client_len = sizeof(client_addr);
                int client_fd = accept(listen_web_fd, (struct sockaddr *)&client_addr, &client_len);
                if (client_fd < 0) continue;

                char client_ip[32];
                inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));

                // ENFORCE WHITELIST
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
                // Connection event (read or hangup)
                // Determine whether it is an agent connection or HTTP connection by examining structure
                // We use first field (which is fd in both structs) to inspect.
                // To safely distinguish, we can read the event flags
                uint32_t epoll_events = events[i].events;

                if (epoll_events & (EPOLLRDHUP | EPOLLHUP | EPOLLERR)) {
                    // Client disconnected
                    // Free states
                    void *ptr = events[i].data.ptr;
                    int *client_fd_ptr = (int *)ptr;
                    if (client_fd_ptr) {
                        int client_fd = *client_fd_ptr;
                        printf("[receiver] Connection closed on fd %d\n", client_fd);
                        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, client_fd, NULL);
                        close(client_fd);
                        sse_remove(client_fd); // Remove if it was an SSE client
                        free(ptr);
                    }
                    continue;
                }

                // Identify if it's an HTTP connection or Agent connection
                // We can structure the first int of both states to hold a type identifier or inspect the sockets
                // Let's look up the port or just cast safely. To do this, let's look at the structure sizes:
                // struct agent_connection is large (BUFFER_SIZE bytes), struct http_connection is small.
                // Alternatively, we can check by getting socket name/peer name port, or simpler:
                // We can add a 'type' field to the start of the structs!
                // Struct structure:
                // struct agent_connection { int fd; int type; ... }
                // struct http_connection  { int fd; int type; ... }
                // Let's modify the struct definitions to hold a 'type' flag: type 1 = agent, type 2 = web.
                // Let's cast to a generic header.
                struct generic_conn {
                    int fd;
                    int type; // 1 = agent, 2 = web
                } *g_conn = (struct generic_conn *)events[i].data.ptr;

                if (!g_conn) continue;

                if (g_conn->type == 0) {
                    // Oh, we didn't initialize the type.
                    // Let's see: struct agent_connection was allocated with calloc, type is at offset 4.
                    // We should have initialized it. Let's make sure we initialize conn->type!
                    // Let's look at the accept handler: we calloc'd the structs but didn't set type!
                    // Let's write the read code now, and we'll fix the accept handler later or handle it.
                }

                // Let's differentiate based on the pointer
                // Wait! Since we know what fd they hold, we can check the socket's local port using getsockname!
                // This is 100% reliable and requires no struct padding checks.
                struct sockaddr_in local_addr;
                socklen_t addr_len = sizeof(local_addr);
                getsockname(g_conn->fd, (struct sockaddr *)&local_addr, &addr_len);
                int local_port = ntohs(local_addr.sin_port);

                if (local_port == PORT_AGENT) {
                    // Agent connection data incoming
                    struct agent_connection *conn = (struct agent_connection *)events[i].data.ptr;
                    
                    // Read header first if not already received
                    if (!conn->header_received) {
                        int needed = sizeof(struct soc_msg_hdr) - conn->bytes_read;
                        int r = read(conn->fd, ((char *)&conn->hdr) + conn->bytes_read, needed);
                        if (r <= 0) {
                            if (r < 0 && errno == EAGAIN) continue;
                            // Disconnect
                            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, conn->fd, NULL);
                            close(conn->fd);
                            free(conn);
                            continue;
                        }
                        conn->bytes_read += r;
                        if (conn->bytes_read == sizeof(struct soc_msg_hdr)) {
                            conn->header_received = 1;
                            conn->payload_len = ntohl(conn->hdr.payload_len);
                            conn->bytes_read = 0; // reset for payload reading
                            
                            // Check header magic
                            if (ntohl(conn->hdr.magic) != MAGIC_HEADER) {
                                fprintf(stderr, "[receiver] Invalid header magic from %s. Disconnecting.\n", conn->client_ip);
                                epoll_ctl(epoll_fd, EPOLL_CTL_DEL, conn->fd, NULL);
                                close(conn->fd);
                                free(conn);
                                continue;
                            }

                            if (conn->payload_len >= BUFFER_SIZE) {
                                fprintf(stderr, "[receiver] Payload too large (%d bytes). Disconnecting.\n", conn->payload_len);
                                epoll_ctl(epoll_fd, EPOLL_CTL_DEL, conn->fd, NULL);
                                close(conn->fd);
                                free(conn);
                                continue;
                            }
                        }
                    }

                    // Read payload
                    if (conn->header_received) {
                        if (conn->payload_len == 0) {
                            // Heartbeat ping (no payload)
                            process_agent_message(conn);
                            conn->header_received = 0;
                            conn->bytes_read = 0;
                        } else {
                            int needed = conn->payload_len - conn->bytes_read;
                            int r = read(conn->fd, conn->buf + conn->bytes_read, needed);
                            if (r <= 0) {
                                if (r < 0 && errno == EAGAIN) continue;
                                epoll_ctl(epoll_fd, EPOLL_CTL_DEL, conn->fd, NULL);
                                close(conn->fd);
                                free(conn);
                                continue;
                            }
                            conn->bytes_read += r;
                            if (conn->bytes_read == conn->payload_len) {
                                // Full payload received, process it
                                process_agent_message(conn);
                                // Reset state for next message
                                conn->header_received = 0;
                                conn->bytes_read = 0;
                            }
                        }
                    }
                } 
                else if (local_port == PORT_WEB) {
                    // HTTP Client data incoming
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

                    // Check if request headers are fully read (ends in \r\n\r\n)
                    char *end_headers = strstr(conn->buf, "\r\n\r\n");
                    if (end_headers) {
                        // Parse HTTP Request
                        char method[16] = {0}, path[512] = {0};
                        sscanf(conn->buf, "%15s %511s", method, path);

                        // Extract Cookie header
                        char *cookie_header = strcasestr(conn->buf, "Cookie:");
                        char cookie_val[512] = {0};
                        if (cookie_header) {
                            sscanf(cookie_header, "Cookie: %511[^\r\n]", cookie_val);
                        }

                        // Extract Content-Length for POST body
                        char *cl_header = strcasestr(conn->buf, "Content-Length:");
                        int content_length = 0;
                        if (cl_header) {
                            content_length = atoi(cl_header + 15);
                        }

                        char *body_start = end_headers + 4;
                        int body_read = conn->bytes_read - (body_start - conn->buf);

                        // If it's a POST request, make sure we have read the complete body
                        if (strcmp(method, "POST") == 0 && body_read < content_length) {
                            // Wait for more data in next epoll loop
                            continue;
                        }

                        // Route HTTP request
                        if (strncmp(path, "/api/", 5) == 0 || strcmp(path, "/auth") == 0) {
                            handle_api_request(conn->fd, method, path, body_start, strlen(cookie_val) > 0 ? cookie_val : NULL);
                        } else {
                            serve_static_file(conn->fd, path);
                        }

                        // Close client unless it's SSE (/api/events/live)
                        // SSE handler removes fd from epoll and doesn't close it.
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

    db_close();
    close(listen_agent_fd);
    close(listen_web_fd);
    return 0;
}
