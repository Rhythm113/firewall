# Testing and Engine Validation Guide

This guide describes how to run validation test suites to verify the Nullsploit WAF engine's threat detection capability.

============================================================
1. STANDALONE C ENGINE TESTS
============================================================
The core detection logic (SQLi, CMDi, LFI/RFI, Bot User-Agents, IP Reputation, IP Blocklist, SYN Flood rate limits, and Slowloris header timeouts) can be validated in userspace compatibility mode.

Step 1: Execute the Linux test runner script:
$ chmod +x tests/run_tests.sh
$ ./tests/run_tests.sh

Step 2: Verify the output shows all tests passed successfully:
--- Running HTTP Inspector Tests ---
  Test 1 (Benign HTTP GET): Passed
  Test 2 (PHP Shell Injection): Passed
  Test 3 (XSS script Vector): Passed
  Test 4 (Near-match Safe String): Passed
--- Running SQLi, CMDi, Path/LFI/RFI, Bot, and IP reputation Tests ---
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

============================================================
2. INTEGRATION AND REST API TESTS
============================================================
Once the containers are running, you can test specific API endpoints and filter inputs using command-line commands.

Test Case 1: Fetch stats filtered by timeframe and agent node:
$ curl "http://localhost:8443/api/v2/dashboard/stats?timeframe=24h&agent=all"

Test Case 2: Query security logs with keyword search filters:
$ curl "http://localhost:8443/api/v2/events?search=192.168&severity=2&limit=50&offset=0"

Test Case 3: Trigger SMTP notification connection test:
$ curl -X POST "http://localhost:8443/api/v2/config/test-email"

Test Case 4: File upload threat detection YARA validation:
Submit a file containing signature strings (e.g. PHP shells containing eval() or system() commands) to the uploads endpoint:
$ curl -F "file=@/tmp/evil_upload.php" http://localhost/upload.php
Check /var/log/firewall/alerts.log inside the WAF container to verify the YARA scan hit:
$ docker compose exec apache-server-1 cat /var/log/firewall/alerts.log
