#!/bin/bash
# Nullsploit WAF Integration Test Script

echo "=================================================="
echo "Running Nullsploit WAF Integration Tests..."
echo "=================================================="

# 1. Check if all containers are running
echo "[+] Checking running containers..."
docker ps --filter "name=apache-2.4.26-node1" --filter "status=running" | grep -q "apache-2.4.26-node1"
if [ $? -ne 0 ]; then
    echo "[-] Error: apache-2.4.26-node1 container is not running!"
    exit 1
fi

# 2. Test benign request (should return 200 OK)
echo "[+] Testing benign HTTP request from host..."
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:80 | grep -q "200"
if [ $? -ne 0 ]; then
    echo "[-] Error: Benign request failed!"
    exit 1
fi
echo "[OK] Benign request returned 200 OK."

# 3. Trigger SQL Injection attack from postgres container (non-bypassed IP)
echo "[+] Triggering SQL Injection attack from within the network..."
# This should trigger WAF rule and lower reputation score, resulting in auto-block
docker exec soc-postgres wget --timeout=5 --tries=1 -qO- --spider "http://apache-2.4.26-node1/index.html?id=1%20UNION%20SELECT%20null,username,password%20FROM%20users" >/dev/null 2>&1

echo "[+] Waiting for reputation check & auto-block sync (30 seconds)..."
sleep 30

# 4. Check if the postgres container IP is blocked on Node 2
echo "[+] Verifying if postgres IP was auto-blocked on Node 2..."
# We try to connect from postgres container to Node 2 (apache-2.4.26-node2). It should time out/fail (WAF drop verdict).
docker exec soc-postgres wget --timeout=5 --tries=1 -qO- --spider "http://apache-2.4.26-node2/index.html" >/dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "[-] Error: IP blocklist sync failed! Postgres container is still allowed to hit Node 2."
    exit 1
fi
echo "[OK] IP blocklist sync successfully blocked postgres IP on Node 2!"

# 5. Clear reputation and verify unblock sync
echo "[+] Clearing IP reputation for postgres..."
TOKEN=$(curl -s -X POST -H "Content-Type: application/json" -d '{"username":"admin","password":"password"}' http://localhost:8443/api/v2/auth | grep -o '"token":"[^"]*' | grep -o '[^"]*$')
curl -s -X DELETE -H "X-Session-Token: $TOKEN" "http://localhost:8443/api/v2/reputation?ip=172.18.0.2" >/dev/null 2>&1

echo "[+] Waiting for unblock sync (5 seconds)..."
sleep 5

echo "[+] Verifying if postgres IP is unblocked on Node 2..."
NODE2_IP=$(docker exec soc-postgres getent hosts apache-2.4.26-node2 | awk '{print $1}')
docker exec soc-postgres wget --user-agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)" --timeout=5 --tries=1 -qO- --spider "http://$NODE2_IP/index.html" >/dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "[-] Error: IP reputation unblock sync failed! Postgres container is still blocked."
    exit 1
fi
echo "[OK] IP reputation unblock sync successfully unblocked postgres IP on Node 2!"

echo "=================================================="
echo "ALL INTEGRATION TESTS PASSED SUCCESSFULLY!"
echo "=================================================="
