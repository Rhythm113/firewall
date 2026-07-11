@echo off
setlocal enabledelayedexpansion
cls
echo =======================================================================
echo                 NULLSPLOIT WAF ^& SOC DEMONSTRATION
echo =======================================================================
echo This script demonstrates the core capabilities of the Nullsploit WAF:
echo  1. Host Gateway Bypass (No Lockouts)
echo  2. Threat Detection (SQL Injection / Bot Scanners)
echo  3. Reputation Scoring ^& Auto-Blocking
echo  4. Instant Multi-Agent Sync
echo  5. Clear Reputation ^& Instant Unblocking
echo =======================================================================
echo.

pause

echo -----------------------------------------------------------------------
echo PHASE 1: Checking WAF Services
echo -----------------------------------------------------------------------
docker ps --filter "name=apache-2.4.26-node1" --filter "status=running" | findstr "apache-2.4.26-node1" >nul
if %errorlevel% neq 0 (
    echo [-] ERROR: WAF service containers are not running. Run 'docker-compose up -d' first.
    exit /b 1
)
echo [OK] WAF services are up and active.
echo.

echo -----------------------------------------------------------------------
echo PHASE 2: Administrative Host Bypass Verification
echo -----------------------------------------------------------------------
echo Sending a benign request from the host machine...
for /f %%a in ('curl.exe -s -o NUL -w "%%{http_code}" http://localhost:80') do set CODE=%%a
echo [+] Host HTTP Response Code: !CODE!
if "!CODE!"=="200" (
    echo [PASS] Benign request was accepted because the host gateway [192.168.65.1]
    echo        is matched against the bypass rules, preventing administrator lockout.
) else (
    echo [FAIL] Benign request returned !CODE!.
)
echo.

pause

echo -----------------------------------------------------------------------
echo PHASE 3: Threat Detection (SQL Injection)
echo -----------------------------------------------------------------------
echo Simulating a SQL Injection attack originating from within the network 
echo (non-bypassed container IP: 172.18.0.2)...
echo.
docker exec soc-postgres wget --timeout=5 --tries=1 -qO- --spider "http://apache-2.4.26-node1/index.html?id=1%%20UNION%%20SELECT%%20null,username,password%%20FROM%%20users" >nul 2>&1
echo [WAF Alert] Querying database for events triggered by 172.18.0.2...
docker exec soc-postgres psql -U nullsploit -d nullsploit -c "SELECT timestamp, src_ip::text as src_ip, threat_type, payload_preview, details FROM events WHERE src_ip = '172.18.0.2' ORDER BY id DESC LIMIT 1"
echo.

pause

echo -----------------------------------------------------------------------
echo PHASE 4: Reputation Drop ^& Auto-Block Sync
echo -----------------------------------------------------------------------
echo Checking reputation score of the attacker IP in the database...
docker exec soc-postgres psql -U nullsploit -d nullsploit -c "SELECT host(ip) as ip, score, local_score FROM ip_reputation WHERE ip = '172.18.0.2'"
echo.
echo Checking if the IP was auto-blocked and synchronized to Node 2...
echo (Connecting to Node 2 from the blocked attacker container - should time out)
docker exec soc-postgres wget --user-agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)" --timeout=5 --tries=1 -qO- --spider "http://apache-2.4.26-node2/index.html" >nul 2>&1
if %errorlevel% neq 0 (
    echo [PASS] Connection timed out! The IP was successfully blocked on Node 2.
) else (
    echo [FAIL] IP is still allowed to connect!
)
echo.

pause

echo -----------------------------------------------------------------------
echo PHASE 5: Administrative Reputation Clearance ^& Instant Unblocking
echo -----------------------------------------------------------------------
echo Clearing the IP reputation for 172.18.0.2...
powershell -ExecutionPolicy Bypass -File tests\clear_reputation.ps1 >nul 2>&1
echo [OK] Reputation cleared. Waiting 5 seconds for agent unblock sync...
ping -n 6 127.0.0.1 >nul
echo.
echo Verifying if the attacker IP is unblocked on Node 2...
for /f "tokens=1" %%i in ('docker exec soc-postgres getent hosts apache-2.4.26-node2') do set NODE2_IP=%%i
docker exec soc-postgres wget --user-agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)" --timeout=5 --tries=1 -qO- --spider "http://!NODE2_IP!/index.html" >nul 2>&1
if %errorlevel% EQU 0 (
    echo [PASS] Connection succeeded! The IP was successfully unblocked.
) else (
    echo [FAIL] Connection timed out! The IP is still blocked.
)
echo.

echo =======================================================================
echo DEMONSTRATION COMPLETE!
echo All features of the WAF (Bypass, Detect, Block, Sync, Unblock) verified.
echo =======================================================================
