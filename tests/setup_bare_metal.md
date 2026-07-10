# Setup Guide: Bare Metal Deployment

This guide explains how to install and compile the Nullsploit WAF firewall engine and SOC server directly on a Linux host (Ubuntu/Debian) without using Docker containers.

============================================================
1. SYSTEM PREREQUISITES
============================================================
Install the following compilation dependencies and system libraries:
$ sudo apt-get update
$ sudo apt-get install -y build-essential libpq-dev libssl-dev \
    libcurl4-openssl-dev libyara-dev iptables gnupg \
    openjdk-17-jre-headless maven postgresql postgresql-contrib

============================================================
2. POSTGRES DATABASE CONFIGURATION
============================================================
Set up the PostgreSQL database server:

Step 1: Log in to postgres user session:
$ sudo -i -u postgres psql

Step 2: Execute database configuration commands:
CREATE DATABASE nullsploit;
CREATE USER nullsploit WITH PASSWORD 'nullsploit_secure';
GRANT ALL PRIVILEGES ON DATABASE nullsploit TO nullsploit;
\q

============================================================
3. COMPILATION AND INSTALLATION
============================================================

Step 1: Build the SOC Ingest Receiver Daemon:
$ cd soc-server
$ make clean && make
$ cd ..

Step 2: Build the Java Spring Boot Console Console:
$ cd soc-server/dashboard-spring
$ mvn clean package -DskipTests
$ cd ../..

Step 3: Build the Kernel Firewall Netfilter Hook:
$ cd kernel
$ make clean && make
$ cd ..

Step 4: Build the Userspace Agent:
$ cd agent
$ make clean && make
$ cd ..

============================================================
4. SERVICE SETUP
============================================================

Step 1: Run the C Ingest Receiver:
Set environment variables for PostgreSQL connection details:
$ export PGHOST=127.0.0.1
$ export PGPORT=5432
$ export PGDATABASE=nullsploit
$ export PGUSER=nullsploit
$ export PGPASSWORD=nullsploit_secure
$ ./soc-server/soc_receiver &

Step 2: Run the Java Console Console:
$ java -jar soc-server/dashboard-spring/target/dashboard-1.0.0.jar &

Step 3: Setup IPTables Redirection Rules:
$ sudo iptables -A INPUT -p tcp --dport 80 -j NFQUEUE --queue-num 0

Step 5: Start Netfilter Hook and Unix Agent:
$ sudo ./kernel/fw_nfq &
$ ./agent/fw_agent &
