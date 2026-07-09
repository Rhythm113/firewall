#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include "yara_engine.h"

#ifdef HAS_YARA
#include <yara.h>
static YR_RULES *compiled_rules = NULL;
#endif

// Async upload queue structure
#define QUEUE_SIZE 256
static char *upload_queue[QUEUE_SIZE];
static int queue_head = 0;
static int queue_tail = 0;
static pthread_mutex_t queue_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;
static pthread_t worker_thread;
static int worker_running = 0;
static int yara_initialized = 0;
static char yara_rules_dir[256];

extern void send_fw_event(void *event); // We will define the full event trigger

#ifdef HAS_YARA
// Callback function for YARA scanner
static int yara_scan_callback(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data) {
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        YR_RULE* rule = (YR_RULE*)message_data;
        char *matched_name = (char *)user_data;
        strncpy(matched_name, rule->identifier, 127);
        matched_name[127] = '\0';
        return CALLBACK_ABORT; // Stop scanning after first match to be fast
    }
    return CALLBACK_CONTINUE;
}
#endif

// Worker thread for async file upload scanning
static void *yara_worker_thread(void *arg) {
    while (worker_running) {
        char *filepath = NULL;

        pthread_mutex_lock(&queue_lock);
        while (queue_head == queue_tail && worker_running) {
            pthread_cond_wait(&queue_cond, &queue_lock);
        }
        if (!worker_running) {
            pthread_mutex_unlock(&queue_lock);
            break;
        }

        filepath = upload_queue[queue_tail];
        queue_tail = (queue_tail + 1) % QUEUE_SIZE;
        pthread_mutex_unlock(&queue_lock);

        if (filepath) {
            printf("[yara_engine] Async scanning file upload: %s\n", filepath);
            
            // Perform scan
            char matched[128] = {0};
            int hit = 0;

#ifdef HAS_YARA
            if (compiled_rules) {
                int err = yr_rules_scan_file(compiled_rules, filepath, 0, yara_scan_callback, matched, 0);
                if (err == ERROR_SUCCESS && matched[0] != '\0') {
                    hit = 1;
                }
            }
#else
            // Mock YARA scanner: scans file for basic webshell signatures
            FILE *f = fopen(filepath, "r");
            if (f) {
                char buf[4096];
                int n = fread(buf, 1, sizeof(buf) - 1, f);
                if (n > 0) {
                    buf[n] = '\0';
                    if (strstr(buf, "eval(") || strstr(buf, "passthru(") || strstr(buf, "system(") || strstr(buf, "exec(")) {
                        hit = 1;
                        strcpy(matched, "Mock_PHP_Webshell");
                    }
                }
                fclose(f);
            }
#endif

            if (hit) {
                printf("[yara_engine] ALERT! YARA matched: %s on file: %s\n", matched, filepath);
                // In production, we'd trigger a security event to send to the SOC server.
                // We'll write to alerts.log (which the agent watches) so that the agent picks it up!
                FILE *alert_log = fopen("/var/log/firewall/alerts.log", "a");
                if (alert_log) {
                    time_t now = time(NULL);
                    fprintf(alert_log, "[%ld] [YARA_THREAT] [CRITICAL] File upload matched YARA rule %s: %s\n", 
                            now, matched, filepath);
                    fclose(alert_log);
                }
            } else {
                printf("[yara_engine] YARA scan clean for file: %s\n", filepath);
            }

            free(filepath);
        }
    }
    return NULL;
}

int init_yara_engine(const char *rules_dir) {
    if (yara_initialized) return 0;
    strncpy(yara_rules_dir, rules_dir, sizeof(yara_rules_dir) - 1);

#ifdef HAS_YARA
    int err = yr_initialize();
    if (err != ERROR_SUCCESS) {
        fprintf(stderr, "[yara_engine] Failed to initialize libyara: %d\n", err);
        return -1;
    }

    YR_COMPILER *compiler = NULL;
    err = yr_compiler_create(&compiler);
    if (err != ERROR_SUCCESS) {
        fprintf(stderr, "[yara_engine] Failed to create YARA compiler: %d\n", err);
        yr_finalize();
        return -1;
    }

    // Try loading signatures/yara/rules.yar
    char rules_file[512];
    snprintf(rules_file, sizeof(rules_file), "%s/rules.yar", rules_dir);
    FILE *f = fopen(rules_file, "r");
    if (f) {
        err = yr_compiler_add_file(compiler, f, NULL, rules_file);
        fclose(f);
        if (err != 0) {
            fprintf(stderr, "[yara_engine] YARA compile error in file %s\n", rules_file);
            yr_compiler_destroy(compiler);
            yr_finalize();
            return -1;
        }

        err = yr_compiler_get_rules(compiler, &compiled_rules);
        if (err != ERROR_SUCCESS) {
            fprintf(stderr, "[yara_engine] Failed to get YARA rules: %d\n", err);
            yr_compiler_destroy(compiler);
            yr_finalize();
            return -1;
        }
    } else {
        printf("[yara_engine] No rules.yar found at %s. Initialized with empty rule set.\n", rules_file);
    }
    yr_compiler_destroy(compiler);
#else
    printf("[yara_engine] Compiling without HAS_YARA macro. Using mock engine.\n");
#endif

    // Start background file scanning thread (1 worker thread)
    worker_running = 1;
    if (pthread_create(&worker_thread, NULL, yara_worker_thread, NULL) != 0) {
        fprintf(stderr, "[yara_engine] Failed to create worker thread\n");
        cleanup_yara_engine();
        return -1;
    }

    yara_initialized = 1;
    printf("[yara_engine] YARA engine initialized successfully.\n");
    return 0;
}

void cleanup_yara_engine(void) {
    if (!yara_initialized) return;

    // Stop worker thread
    pthread_mutex_lock(&queue_lock);
    worker_running = 0;
    pthread_cond_broadcast(&queue_cond);
    pthread_mutex_unlock(&queue_lock);

    pthread_join(worker_thread, NULL);

    // Empty queue
    pthread_mutex_lock(&queue_lock);
    while (queue_head != queue_tail) {
        free(upload_queue[queue_tail]);
        queue_tail = (queue_tail + 1) % QUEUE_SIZE;
    }
    pthread_mutex_unlock(&queue_lock);

#ifdef HAS_YARA
    if (compiled_rules) {
        yr_rules_destroy(compiled_rules);
        compiled_rules = NULL;
    }
    yr_finalize();
#endif

    yara_initialized = 0;
    printf("[yara_engine] YARA engine shut down successfully.\n");
}

int scan_mem_yara(const char *buf, int len, char *matched_rule, int max_rule_len) {
    if (!yara_initialized) return 0;
    matched_rule[0] = '\0';

#ifdef HAS_YARA
    if (!compiled_rules) return 0;

    char matched[128] = {0};
    int err = yr_rules_scan_mem(compiled_rules, (const uint8_t *)buf, len, 0, yara_scan_callback, matched, 0);
    if (err == ERROR_SUCCESS && matched[0] != '\0') {
        strncpy(matched_rule, matched, max_rule_len - 1);
        matched_rule[max_rule_len - 1] = '\0';
        return 1;
    }
    return 0;
#else
    // Mock inline scanner: match base64_decode or system in payload
    if (strstr(buf, "base64_decode(") || strstr(buf, "system(")) {
        strncpy(matched_rule, "Mock_Webshell_Inline", max_rule_len - 1);
        matched_rule[max_rule_len - 1] = '\0';
        return 1;
    }
    return 0;
#endif
}

void queue_file_upload_scan(const char *filepath) {
    if (!yara_initialized) return;

    pthread_mutex_lock(&queue_lock);
    
    // Check if queue is full
    int next_head = (queue_head + 1) % QUEUE_SIZE;
    if (next_head == queue_tail) {
        fprintf(stderr, "[yara_engine] Queue is full, dropping file scan: %s\n", filepath);
        pthread_mutex_unlock(&queue_lock);
        return;
    }

    upload_queue[queue_head] = strdup(filepath);
    queue_head = next_head;
    
    pthread_cond_signal(&queue_cond);
    pthread_mutex_unlock(&queue_lock);
}
