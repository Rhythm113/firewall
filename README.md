# Apache 2.4.26 Docker Web Server

This project provides a Docker configuration for building and running an **Apache HTTP Server (version 2.4.26)** compiled from source. It includes configuration to expose the web server on your local area network (LAN) so that other devices (such as mobile phones, laptops, or tablets on the same network) can access it using your desktop's LAN IP address.

## Project Structure
- [Dockerfile](file:///d:/NSU/apache-firewall/Dockerfile): Multi-stage build that compiles Apache 2.4.26 from source with `apr`, `apr-util`, and other dependencies, and exports a minimal, secure runtime image.
- [docker-compose.yml](file:///d:/NSU/apache-firewall/docker-compose.yml): Declares configuration to build and run the web server container easily.
- [index.html](file:///d:/NSU/apache-firewall/index.html): A modern, premium-designed landing page to verify that your web server is online.

---

## Step 1: Find Your Desktop's LAN IP Address
To access the container from other devices on your local network, you need to know your desktop's LAN IP address.

### On Windows:
1. Open **PowerShell** or **Command Prompt**.
2. Run the following command:
   ```powershell
   ipconfig
   ```
3. Look for your active network adapter (e.g., `Ethernet adapter` or `Wireless LAN adapter Wi-Fi`).
4. Find the **IPv4 Address** (typically starts with `192.168.x.x` or `10.x.x.x`). This is your desktop's LAN IP address.

---

## Step 2: Build and Run the Container

You can build and run the web server using either **Docker Compose** (recommended) or the **Docker CLI**.

### Option A: Using Docker Compose (Recommended)
1. Open your terminal in this directory.
2. Run the following command to build and launch the container:
   ```bash
   docker compose up -d --build
   ```
3. To stop the container, run:
   ```bash
   docker compose down
   ```

### Option B: Using Docker CLI
1. Build the Docker image:
   ```bash
   docker build -t apache-2.4.26 .
   ```
2. Run the container and publish port 80 to the host:
   ```bash
   docker run -d -p 80:80 --name apache-server apache-2.4.26
   ```
   *Note: Publishing with `-p 80:80` binds to all network interfaces (`0.0.0.0`) on your computer, automatically allowing access via localhost and your LAN IP.*

3. (Optional) If you want to bind **only** to your specific LAN IP (e.g., `192.168.1.100`), run:
   ```bash
   docker run -d -p 192.168.1.100:80:80 --name apache-server apache-2.4.26
   ```

---

## Step 3: Access the Web Server
Once the container is running:
- **On your desktop:** Open your browser and go to `http://localhost` (or `http://127.0.0.1`).
- **On any other device on your LAN:** Open a browser and enter your desktop's LAN IP address:
  ```text
  http://<YOUR_DESKTOP_LAN_IP>/
  ```
  *(Example: `http://192.168.1.100/`)*
