# Detection Engines

## http_inspect.c

The main HTTP payload inspection entry point. Called from
fw_nfq_callback() when the intercepted packet targets port 80 (HTTP).

Flow:
1. Parse the raw HTTP request (URL-decode query string and body)
2. Run through detection chain in priority order:
   a. SQL injection (detect_sqli)
   b. Command injection (detect_cmdi)
   c. Path traversal / LFI / RFI (detect_path_traversal)
   d. Bot / scanner (detect_bot)
   e. PHP shell detection (keyword-based)
   f. XSS detection (keyword-based)
   g. YARA inline memory scan (scan_mem_yara)

First detection wins (short-circuit). Each detection calls
send_fw_event() with the threat type and update_ip_reputation()
with a damage value.

### Damage Values

| Threat Type | Damage to Reputation |
|-------------|---------------------|
| THREAT_PHP_SHELL | 25 |
| THREAT_SQLI | 20 |
| THREAT_CMDI | 20 |
| THREAT_PATH_TRAV | 20 |
| THREAT_BOT | 15 |
| THREAT_XSS | 10 |
| THREAT_YARA | 30 |
| THREAT_SYN_FLOOD | 25 |

The function also registers HTTP header progress with the TCP monitor:
- register_http_header_sent(): called when partial HTTP header data
  is observed
- register_http_complete(): called when \r\n\r\n is seen (request
  complete)

## SQLi Detection (sqli_detect.h / sqli_detect.c)

URL-decodes the input (single decode), then double-decodes if the
result still contains % characters.

### Tokenizer
Splits the decoded payload into up to 128 tokens. Tokens are separated
by whitespace, SQL operators, and punctuation.

### Pattern Recognition (scoring)

| Pattern | Score | Description |
|---------|-------|-------------|
| UNION SELECT | 45 | Classic SQL union injection |
| TAUTOLOGY | 45 | OR/AND with always-true condition (1=1) |
| ADMIN BYPASS | 45 | ' OR '1'='1' -- patterns |
| STACKED QUERIES | 40 | Multiple statements with ; |
| ERROR FUNCTIONS | 25 | extractvalue, updatexml, etc. |
| TIME FUNCTIONS | 35 | sleep(), benchmark(), pg_sleep() |
| FILE WRITE | 35 | INTO OUTFILE, INTO DUMPFILE |
| INLINE COMMENT | 10 | /*! or -- style comments |

### Raw Pattern Fallback
If the decoded text contains "union select" or "or 1=1" as substrings,
immediately score 40.

### Threshold
score >= 40 -> SQL injection detected.

### Details
Descriptive string showing which patterns matched with their scores.

## CMDi Detection (cmdi_detect.h / cmdi_detect.c)

URL-decodes + double-decodes the input.

### Detection Checks

| Check | Score | Description |
|-------|-------|-------------|
| Shell metacharacters | 15 | ;, |, &&, `, $(), <> |
| Dangerous commands | 20 each | whoami, nc, bash, python, perl, etc. |
| /etc/passwd or /etc/shadow | 35 | File path references |
| /bin/sh or /bin/bash | 30 | Shell path references |
| /dev/tcp/ | 40 | Reverse shell via TCP |
| combined meta+command | +25 | Metachar + command present |
| sh -i or bash -i | 50 | Interactive shell attempt |

### Threshold
score >= 40 -> command injection detected.

## Path Traversal / LFI / RFI Detection (path_detect.h / path_detect.c)

URL-decodes + double-decodes the input.

### Detection Checks

| Check | Score | Description |
|-------|-------|-------------|
| Traversal sequences (../, ..\\, ..;) | 15 each | Directory traversal |
| LFI targets | 35 | /etc/passwd, /etc/shadow, boot.ini, etc. |
| PHP wrappers | 45 | php://, data://, zip://, phar:// |
| RFI URLs | 45 | http://, https://, ftp:// after = |
| Null byte | 15 | %00 or literal NUL |

### Threshold
score >= 40 -> path traversal / LFI / RFI detected.

## Bot / Scanner Detection (bot_detect.h / bot_detect.c)

Parses the raw HTTP request to extract the method, path, and
User-Agent header.

### Detection Checks

| Check | Score | Description |
|-------|-------|-------------|
| Scanner User-Agent | 45 | sqlmap, nikto, dirbuster, nmap, etc. |
| Empty User-Agent | 20 | No UA header present |
| Honeypot path | 45 | /wp-login, /phpmyadmin, /.git, etc. |
| Combined (UA + honeypot) | +10 | Both match |

### Threshold
score >= 40 -> bot/scanner detected.

## PHP Shell Detection

Inline keyword check in http_inspect.c for PHP function names:
- eval(
- system(
- exec(
- shell_exec(
- passthru(
- assert(
- preg_replace (with /e modifier)
- create_function
- array_map
- call_user_func

If found, triggers THREAT_PHP_SHELL.

## XSS Detection

Inline keyword check in http_inspect.c for:
- <script>
- onload=
- onerror=
- javascript:
- <iframe
- <embed
- <object
- <svg

If found, triggers THREAT_XSS.

## YARA Scanning (yara_engine.h / yara_engine.c)

Two scan paths:

### Inline Memory Scan (scan_mem_yara)
Called from http_inspect.c during packet evaluation. Uses
yr_rules_scan_mem() on the raw HTTP payload buffer. Matches are
logged and trigger THREAT_YARA.

### Async File Upload Scan
A background worker thread with a condition-variable-based queue
(QUEUE_SIZE=256). Files are added via queue_file_upload_scan().
The worker scans each file with yr_rules_scan_file() and writes
matches to /var/log/firewall/alerts.log.

### Engine Initialization
- init_yara_engine(): Compiles YARA rules from
  /etc/fw_inspect/yara/rules.yar into yr_compiler. Falls back to
  mock scanning if HAS_YARA is not defined (checks for eval,
  passthru, system, exec strings in input).
- cleanup_yara_engine(): Signals shutdown, joins the async worker
  thread, destroys compiled rules, calls yr_finalize().

## Build Dependencies

- SQLi, CMDi, Path, Bot: No external dependencies
- YARA: libyara-dev (yr_compiler, yr_rules)

All detection sources are at kernel/*.c and kernel/*.h.
They are compiled with -DBUILD_USERSPACE -DHAS_YARA.
