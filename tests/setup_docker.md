# Setup Guide: Docker Deployment

This guide explains how to deploy the Nullsploit WAF firewall and SOC server in a multi-container environment using Docker and Docker Compose.

============================================================
1. PREREQUISITES
============================================================
Ensure your host machine has the following packages installed:
* Docker Engine (v20.10 or higher)
* Docker Compose (v2.0 or higher)
* GnuPG (for key verification checks on the host, optional)

============================================================
2. DIRECTORY STRUCTURE
============================================================
The project contains the following core layout:
* /soc-server: Contains the SOC ingest receiver daemon and the Java Spring Boot console.
* /kernel: Contains WAF Netfilter Hook rules and signature match modules.
* /agent: Contains the userspace UNIX socket agent broker.
* /signatures: Holds rule files like blocklists and YARA rule sets.
* /keys: Shared volume directory for exchanging PGP public keys between containers.

============================================================
3. DOCKER COMPOSE CONFIGURATION
============================================================
The architecture defines four main containers:
1. soc-postgres: Persistent database server (PostgreSQL 15).
2. soc-dashboard: Java Spring Boot REST API console (Port 8443) and C receiver daemon (Port 1113).
3. apache-server-1: Node 1 Apache WAF container (Port 80) intercepting traffic with Netfilter Queue.
4. apache-server-2: Node 2 Apache WAF container (Port 81) running an identical WAF setup.

============================================================
4. DEPLOYMENT STEPS
============================================================
Follow these commands to deploy the container stack:

Step 1: Clean build and wipe old data volumes:
$ docker compose down -v

Step 2: Build and start the container stack:
$ docker compose up -d --build

Step 3: Monitor container startup and log feeds:
$ docker compose logs -f

============================================================
5. VERIFICATION
============================================================
Once the containers are active:
* Access the SOC Dashboard: Open http://localhost:8443 in your browser (Default credentials: admin / password).
* Node 1 Ingress: Verify http://localhost:80 renders the target application page.
* Node 2 Ingress: Verify http://localhost:81 renders the target application page.
* Key Ingest Watcher: Verify PGP keys are generated and swapped inside the ./keys folder.
