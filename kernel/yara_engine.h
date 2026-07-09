#ifndef YARA_ENGINE_H
#define YARA_ENGINE_H

/**
 * Initializes the YARA rule engine.
 * Compiles all YARA rules found in the signatures/yara directory.
 * Launches the async file scanning worker thread.
 *
 * @param rules_dir Directory containing .yar rule files.
 * @return 0 on success, -1 on failure.
 */
int init_yara_engine(const char *rules_dir);

/**
 * Destroys and cleans up the YARA rule engine.
 */
void cleanup_yara_engine(void);

/**
 * Scans a memory buffer against compiled rules (inline path).
 *
 * @param buf Memory buffer to scan.
 * @param len Length of the buffer.
 * @param matched_rule Buffer to store the triggered rule name.
 * @param max_rule_len Size of matched_rule buffer.
 * @return 1 if a rule matched, 0 if no match, -1 on error.
 */
int scan_mem_yara(const char *buf, int len, char *matched_rule, int max_rule_len);

/**
 * Queues a file path for background scanning (async path).
 *
 * @param filepath Path to the uploaded file.
 */
void queue_file_upload_scan(const char *filepath);

#endif // YARA_ENGINE_H
