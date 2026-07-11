#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <curl/curl.h>
#include "threat_intel.h"
#include "db.h"

static pthread_t intel_thread;
static int thread_running = 0;
static pthread_mutex_t fetch_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t fetch_cond = PTHREAD_COND_INITIALIZER;
static int fetch_requested = 0;

struct curl_buffer {
    char *data;
    size_t size;
};

static size_t curl_write_cb(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct curl_buffer *mem = (struct curl_buffer *)userp;

    char *ptr = realloc(mem->data, mem->size + realsize + 1);
    if (!ptr) return 0; // OOM

    mem->data = ptr;
    memcpy(&(mem->data[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->data[mem->size] = 0;

    return realsize;
}

// Download URL helper using libcurl
static char *download_url(const char *url) {
    CURL *curl_handle;
    CURLcode res;
    struct curl_buffer chunk;

    chunk.data = malloc(1);
    chunk.size = 0;

    curl_handle = curl_easy_init();
    curl_easy_setopt(curl_handle, CURLOPT_URL, url);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "Nullsploit-SOC/2.0");
    curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT, 15L);
    curl_easy_setopt(curl_handle, CURLOPT_FOLLOWLOCATION, 1L);

    res = curl_easy_perform(curl_handle);

    if (res != CURLE_OK) {
        fprintf(stderr, "[threat_intel] curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        free(chunk.data);
        chunk.data = NULL;
    }

    curl_easy_cleanup(curl_handle);
    return chunk.data;
}

// Feodo Tracker parser
static void fetch_feodo_tracker(void) {
    printf("[threat_intel] Fetching Feodo Tracker botnet IPs...\n");
    char *data = download_url("https://feodotracker.abuse.ch/downloads/ipblocklist.txt");
    if (!data) return;

    char *line = strtok(data, "\r\n");
    int count = 0;
    while (line) {
        // Skip comment lines
        if (line[0] != '#' && strlen(line) > 6) {
            char ip[64] = {0};
            // Format of lines: IP
            sscanf(line, "%63s", ip);
            if (strlen(ip) > 0) {
                db_save_threat_intel("Feodo_Tracker", "ip", ip, "botnet_c2", 90, "https://feodotracker.abuse.ch/");
                db_update_ip_reputation(ip, 15, 100, 15, "botnet_c2"); // Low reputation from known botnet C2
                count++;
            }
        }
        line = strtok(NULL, "\r\n");
    }
    printf("[threat_intel] Imported %d IPs from Feodo Tracker\n", count);
    free(data);
}

// Binary Defense banlist parser
static void fetch_binary_defense(void) {
    printf("[threat_intel] Fetching Binary Defense banlist...\n");
    char *data = download_url("https://www.binarydefense.com/banlist.txt");
    if (!data) return;

    char *line = strtok(data, "\r\n");
    int count = 0;
    while (line) {
        if (line[0] != '#' && strlen(line) > 6) {
            char ip[64] = {0};
            sscanf(line, "%63s", ip);
            if (strlen(ip) > 0) {
                db_save_threat_intel("Binary_Defense", "ip", ip, "malicious_ip", 80, "https://www.binarydefense.com/");
                db_update_ip_reputation(ip, 20, 100, 20, "malicious_ip"); // Low reputation from known malicious IP
                count++;
            }
        }
        line = strtok(NULL, "\r\n");
    }
    printf("[threat_intel] Imported %d IPs from Binary Defense\n", count);
    free(data);
}

// CI Army parser
static void fetch_ci_army(void) {
    printf("[threat_intel] Fetching CI Army bad guys list...\n");
    char *data = download_url("http://cinsscore.com/list/ci-badguys.txt");
    if (!data) return;

    char *line = strtok(data, "\r\n");
    int count = 0;
    while (line) {
        if (line[0] != '#' && strlen(line) > 6) {
            char ip[64] = {0};
            sscanf(line, "%63s", ip);
            if (strlen(ip) > 0) {
                db_save_threat_intel("CI_Army", "ip", ip, "scanner", 75, "http://cinsscore.com/");
                db_update_ip_reputation(ip, 25, 100, 25, "scanner"); // Reduced reputation from known scanner
                count++;
            }
        }
        line = strtok(NULL, "\r\n");
    }
    printf("[threat_intel] Imported %d IPs from CI Army\n", count);
    free(data);
}

static void run_all_fetches(void) {
    fetch_feodo_tracker();
    fetch_binary_defense();
    fetch_ci_army();
}

static void *intel_aggregator_thread(void *arg) {
    curl_global_init(CURL_GLOBAL_DEFAULT);
    
    // Initial fetch on startup
    run_all_fetches();

    while (thread_running) {
        pthread_mutex_lock(&fetch_lock);
        
        // Wait for next manual trigger or timeout (default: every 6 hours)
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += (6 * 3600); // 6 hours

        while (!fetch_requested && thread_running) {
            int rc = pthread_cond_timedwait(&fetch_cond, &fetch_lock, &ts);
            if (rc == ETIMEDOUT) {
                break; // Timeout reached, run fetch
            }
        }
        fetch_requested = 0;
        pthread_mutex_unlock(&fetch_lock);

        if (!thread_running) break;

        printf("[threat_intel] Performing scheduled threat intel feed refresh...\n");
        run_all_fetches();
    }

    curl_global_cleanup();
    return NULL;
}

int init_threat_intel(void) {
    if (thread_running) return 0;

    thread_running = 1;
    if (pthread_create(&intel_thread, NULL, intel_aggregator_thread, NULL) != 0) {
        fprintf(stderr, "[threat_intel] Failed to create aggregator thread\n");
        thread_running = 0;
        return -1;
    }

    printf("[threat_intel] Threat Intelligence Aggregator thread started successfully\n");
    return 0;
}

void cleanup_threat_intel(void) {
    if (!thread_running) return;

    pthread_mutex_lock(&fetch_lock);
    thread_running = 0;
    pthread_cond_signal(&fetch_cond);
    pthread_mutex_unlock(&fetch_lock);

    pthread_join(intel_thread, NULL);
    printf("[threat_intel] Threat Intelligence Aggregator shut down successfully\n");
}

void trigger_feed_fetch(void) {
    pthread_mutex_lock(&fetch_lock);
    fetch_requested = 1;
    pthread_cond_signal(&fetch_cond);
    pthread_mutex_unlock(&fetch_lock);
}
