@echo off
echo ==================================================
echo Running Nullsploit WAF Integration Tests...
echo ==================================================

:: 1. Check if all containers are running
echo [+] Checking running containers...
docker ps --filter "name=apache-2.4.26-node1" --filter "status=running" | findstr "apache-2.4.26-node1" >nul
if %errorlevel% neq 0 (
    echo [-] Error: apache-2.4.26-node1 container is not running!
    exit /b 1
)

:: 2. Test benign request (should return 200 OK)
echo [+] Testing benign HTTP request from host...
curl.exe -s -o NUL -w "%%{http_code}" http://localhost:80 | findstr "200" >nul
if %errorlevel% neq 0 (
    echo [-] Error: Benign request failed!
    exit /b 1
)
echo [OK] Benign request returned 200 OK.

:: 3. Trigger SQL Injection attack from postgres container (non-bypassed IP)
echo [+] Triggering SQL Injection attack from within the network...
docker exec soc-postgres wget --timeout=5 --tries=1 -qO- --spider "http://apache-2.4.26-node1/index.html?id=1%%20UNION%%20SELECT%%20null,username,password%%20FROM%%20users" >nul 2>&1

echo [+] Waiting for reputation check ^& auto-block sync (30 seconds)...
ping -n 31 127.0.0.1 >nul

:: 4. Check if the postgres container IP is blocked on Node 2
echo [+] Verifying if postgres IP was auto-blocked on Node 2...
docker exec soc-postgres wget --timeout=5 --tries=1 -qO- --spider "http://apache-2.4.26-node2/index.html" >nul 2>&1
if %errorlevel% EQU 0 (
    echo [-] Error: IP blocklist sync failed! Postgres container is still allowed to hit Node 2.
    exit /b 1
)
echo [OK] IP blocklist sync successfully blocked postgres IP on Node 2!

:: 5. Clear reputation and verify unblock sync
echo [+] Clearing IP reputation for postgres...
powershell -ExecutionPolicy Bypass -File tests\clear_reputation.ps1 >nul 2>&1

echo [+] Waiting for unblock sync (5 seconds)...
ping -n 6 127.0.0.1 >nul

echo [+] Verifying if postgres IP is unblocked on Node 2...
for /f "tokens=1" %%i in ('docker exec soc-postgres getent hosts apache-2.4.26-node2') do set NODE2_IP=%%i
docker exec soc-postgres wget --user-agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)" --timeout=5 --tries=1 -qO- --spider "http://%NODE2_IP%/index.html" >nul 2>&1
if %errorlevel% neq 0 (
    echo [-] Error: IP reputation unblock sync failed! Postgres container is still blocked.
    exit /b 1
)
echo [OK] IP reputation unblock sync successfully unblocked postgres IP on Node 2!

echo ==================================================
echo ALL INTEGRATION TESTS PASSED SUCCESSFULLY!
echo ==================================================
