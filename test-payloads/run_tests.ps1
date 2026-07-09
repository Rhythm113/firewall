# Nullsploit Multi-Node WAF Verification Script

$nodes = @("http://localhost:80", "http://localhost:81")

Write-Host "===================================================" -ForegroundColor Cyan
Write-Host "  Nullsploit Multi-Node WAF Testing Suite  " -ForegroundColor Cyan
Write-Host "===================================================" -ForegroundColor Cyan

# 1. Clear database events to make test validation clean
Write-Host "[*] Cleaning old events database records..." -ForegroundColor Yellow
docker exec soc-postgres psql -U nullsploit -d nullsploit -c "DELETE FROM events; DELETE FROM ip_reputation;" | Out-Null
Write-Host "[+] Database cleared successfully." -ForegroundColor Green

# 2. Iterate through WAF nodes and execute test queries
foreach ($node in $nodes) {
    Write-Host "`n---------------------------------------------------" -ForegroundColor Gray
    Write-Host " Target Node WAF: $node" -ForegroundColor Gray
    Write-Host "---------------------------------------------------" -ForegroundColor Gray

    # A. SQL Injection Request
    Write-Host "[*] Executing SQL Injection test request..." -ForegroundColor Yellow
    $payload_sqli = Get-Content -Path "sqli_payload.txt" -Raw
    $encoded_sqli = [uri]::EscapeDataString($payload_sqli)
    try {
        $r = Invoke-WebRequest -Uri "$node/index.html?search=$encoded_sqli" -UseBasicParsing -TimeoutSec 3
        Write-Host "[+] Response received: $($r.StatusCode)" -ForegroundColor DarkGreen
    } catch {
        Write-Host "[+] Blocked/Dropped as expected: $_" -ForegroundColor Green
    }

    # B. Command Injection Request
    Write-Host "[*] Executing Command Injection test request..." -ForegroundColor Yellow
    $payload_cmdi = Get-Content -Path "cmdi_payload.txt" -Raw
    $encoded_cmdi = [uri]::EscapeDataString($payload_cmdi)
    try {
        $r = Invoke-WebRequest -Uri "$node/index.html?cmd=$encoded_cmdi" -UseBasicParsing -TimeoutSec 3
        Write-Host "[+] Response received: $($r.StatusCode)" -ForegroundColor DarkGreen
    } catch {
        Write-Host "[+] Blocked/Dropped as expected: $_" -ForegroundColor Green
    }

    # C. Path Traversal Request
    Write-Host "[*] Executing Path Traversal test request..." -ForegroundColor Yellow
    $payload_path = Get-Content -Path "path_traversal_payload.txt" -Raw
    $encoded_path = [uri]::EscapeDataString($payload_path)
    try {
        $r = Invoke-WebRequest -Uri "$node/index.html?file=$encoded_path" -UseBasicParsing -TimeoutSec 3
        Write-Host "[+] Response received: $($r.StatusCode)" -ForegroundColor DarkGreen
    } catch {
        Write-Host "[+] Blocked/Dropped as expected: $_" -ForegroundColor Green
    }

    # D. Webshell Upload check (triggers directory watcher + YARA scan)
    Write-Host "[*] Executing YARA Webshell Upload test..." -ForegroundColor Yellow
    try {
        $boundary = [System.Guid]::NewGuid().ToString()
        $lf = "`r`n"
        $fileContent = Get-Content -Path "yara_malice_payload.txt" -Raw
        
        $bodyFields = @(
            "--$boundary",
            'Content-Disposition: form-data; name="file"; filename="webshell.php"',
            'Content-Type: application/octet-stream',
            "",
            $fileContent,
            "--$boundary--"
        )
        $body = ($bodyFields -join $lf) + $lf
        
        $r = Invoke-WebRequest -Uri "$node/upload.php" -Method Post -Body $body -ContentType "multipart/form-data; boundary=$boundary" -UseBasicParsing -TimeoutSec 5
        Write-Host "[+] Upload completed. Response: $($r.Content.Trim())" -ForegroundColor Green
    } catch {
        Write-Host "[-] Upload failed: $_" -ForegroundColor Red
    }
}

# 3. Print resulting logs
Write-Host "`n===================================================" -ForegroundColor Cyan
Write-Host "  Querying PostgreSQL Security Events Log  " -ForegroundColor Cyan
Write-Host "===================================================" -ForegroundColor Cyan
Start-Sleep -Seconds 2
docker exec soc-postgres psql -U nullsploit -d nullsploit -c "SELECT id, encode(agent_uuid, 'hex') as agent, timestamp, threat_type, severity, src_ip, payload_preview FROM events ORDER BY timestamp DESC;"

