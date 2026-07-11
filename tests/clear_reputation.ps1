$resp = Invoke-RestMethod -Method Post -Uri "http://localhost:8443/api/v2/auth" -ContentType "application/json" -Body '{"username":"admin","password":"password"}'
Invoke-RestMethod -Method Delete -Uri "http://localhost:8443/api/v2/reputation?ip=172.18.0.2" -Headers @{"X-Session-Token"=$resp.token}
