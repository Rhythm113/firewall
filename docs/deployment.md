# Deployment Guide

## Docker Deployment (Primary)

### Files

| File | Purpose |
|------|---------|
| Dockerfile | Apache WAF node build (multi-stage) |
| docker-compose.yml | Service orchestration |
| soc-server/Dockerfile | SOC server + dashboard build (multi-stage) |
| entrypoint.sh | Apache WAF node entrypoint |
| soc-server/entrypoint.sh | SOC server entrypoint |

### Docker Compose Services

```
docker-compose.yml:
  apache-server-1:  WAF node 1 (port 80)
  apache-server-2:  WAF node 2 (port 81)
  soc-server:       SOC receiver + Spring Boot (ports 1113, 8443)
  postgres:         PostgreSQL 15 (port 5432)
```

### Volumes

- signatures/: Mounted to /etc/fw_inspect (blocklist, YARA rules)
- keys/: Mounted to /etc/fw_keys (Agent UUID)
- soc-data/: SOC server persistent data
- pg-data/: PostgreSQL persistent data
- soc-config/: SOC config files (whitelist, users)

### Startup Sequence

1. postgres starts first (no dependencies)
2. soc-server starts after postgres
3. Apache nodes start after soc-server

### Dockerfile (Apache WAF Node)

Multi-stage build:
- Stage 1 (builder): Builds Apache httpd 2.4.26 from source with
  APR 1.6.2 + APR-util 1.6.0, then compiles fw_nfq and fw_agent.
- Stage 2 (runtime): Debian Bullseye slim with runtime libraries,
  iptables, PHP-FPM 7.4, and GnuPG.

Apache is compiled with:
- --prefix=/usr/local/apache2
- --enable-so
- --enable-ssl
- --enable-mods-shared=reallyall

### Dockerfile (SOC Server)

Multi-stage build:
- Stage 1 (java-builder): Maven build of Spring Boot dashboard
- Stage 2 (builder): Compile C soc_receiver with libpq, libssl,
  libcurl, libyara
- Stage 3 (runtime): OpenJDK 17 JRE + runtime libraries

### entrypoint.sh (Apache Node)

On container start:

1. Configure Apache for PHP-FPM proxying (UNIX socket)
2. Set www-data user/group ownership
3. Configure PHP-FPM pool (listen owner/group/mode)
4. Create upload directory with 777 permissions
5. Start PHP-FPM 7.4 daemon
6. Configure iptables NFQUEUE rule for ports 80,443
7. Create default YARA rule file if missing
8. Start fw_nfq in background
9. Start fw_agent in background
10. Start Apache httpd in foreground

### entrypoint.sh (SOC Server)

On container start:

1. Ensure keys directory exists
2. Start soc_receiver in background
3. Start Java Spring Boot dashboard in foreground

## Bare Metal Deployment

### Requirements

- Debian/Ubuntu or RHEL/CentOS
- PostgreSQL 15+
- OpenJDK 17 JRE
- Maven (for building)
- Compilation dependencies:
  build-essential, libpq-dev, libssl-dev, libcurl4-openssl-dev,
  libyara-dev, iptables, gnupg

### Build Steps

```bash
# 1. SOC Receiver
cd soc-server
make clean && make
cd ..

# 2. Spring Boot Dashboard
cd soc-server/dashboard-spring
mvn clean package -DskipTests
cd ../..

# 3. Firewall daemon
cd kernel
make clean && make
cd ..

# 4. Agent
cd agent
make clean && make
cd ..
```

### Database Setup

```bash
sudo -i -u postgres psql
CREATE DATABASE nullsploit;
CREATE USER nullsploit WITH PASSWORD 'nullsploit_secure';
GRANT ALL PRIVILEGES ON DATABASE nullsploit TO nullsploit;
```

### Service Start

```bash
# 1. Set DB env vars
export PGHOST=127.0.0.1 PGPORT=5432 PGDATABASE=nullsploit
export PGUSER=nullsploit PGPASSWORD=nullsploit_secure

# 2. Start C receiver
./soc-server/soc_receiver &

# 3. Start Java dashboard
java -jar soc-server/dashboard-spring/target/dashboard-1.0.0.jar &

# 4. Configure iptables
sudo iptables -A INPUT -p tcp --dport 80 -j NFQUEUE --queue-num 0

# 5. Start firewall and agent
sudo ./kernel/fw_nfq &
./agent/fw_agent &
```

## Production Kernel Module

For production deployments using the kernel module (fw_inspect.ko):

### Build Against Target Kernel

```bash
sudo apt-get install build-essential linux-headers-$(uname -r)
cd kernel/
make modules    # Produces fw_inspect_mod.ko
```

### Install Module

```bash
sudo cp fw_inspect_mod.ko /lib/modules/$(uname -r)/kernel/drivers/net/
sudo depmod -a
echo "fw_inspect_mod" | sudo tee -a /etc/modules
```

### Load Module

```bash
sudo insmod fw_inspect_mod.ko
sudo insmod fw_inspect_mod.ko max_connections=16384
```

Verify: dmesg should show "Firewall module loaded successfully".

### Kernel Compatibility

| Kernel | Tested Distros | Status |
|--------|----------------|--------|
| 3.10.x | CentOS 7, RHEL 7 | Compatible |
| 4.x | Ubuntu 16.04, Debian 9 | Compatible |
| 5.x | Ubuntu 20.04, Debian 11 | Compatible |
| 6.x | Ubuntu 22.04+, Debian 12 | Compatible |

## Verification

After deployment:

1. Dashboard: http://localhost:8443 (login: admin/password)
2. Apache node 1: http://localhost:80
3. Apache node 2: http://localhost:81
