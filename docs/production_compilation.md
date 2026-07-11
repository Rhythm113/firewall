# Production Compilation & Deployment Guide

This document guides you through building, loading, and deploying the **Custom Kernel Firewall (`fw_inspect.ko`)** and its **Userspace Agent (`fw_agent`)** on bare-metal or VM legacy production Linux servers.

---

## 1. Building the Kernel Module

To compile `fw_inspect.ko` for a production server, you must compile it against the **exact kernel version** running on that target server.

### Prerequisites (Target Server)
Install the matching kernel headers, gcc, make, and build-essential packages:
```bash
# Debian / Ubuntu
sudo apt-get update
sudo apt-get install -y build-essential linux-headers-$(uname -r)

# RHEL / CentOS / Rocky Linux
sudo yum install -y gcc make kernel-devel-$(uname -r)
```

### Compilation Steps
1. Copy the `kernel/` source directory to the target server.
2. Build the module:
   ```bash
   cd kernel/
   # Compile only the kernel module (avoiding the userspace NFQ fallback)
   make modules
   ```
3. This generates `fw_inspect_mod.ko` in the directory.

---

## 2. Deploying and Loading the Module

### Testing Load
Load the compiled module manually to verify it initializes correctly:
```bash
# Default load (4096 max connections)
sudo insmod fw_inspect_mod.ko

# Customize maximum tracked connections for heavy-traffic systems
sudo insmod fw_inspect_mod.ko max_connections=16384
```

Verify loading in kernel ring buffer:
```bash
dmesg | tail -n 10
# Expected output:
# [info] fw_inspect: Initializing firewall module
# [info] fw_inspect: Firewall module loaded successfully (max_connections=16384)
```

### Persisting Across Reboots
To load the module automatically at boot:
1. Copy the module to the kernel extra modules directory:
   ```bash
   sudo mkdir -p /lib/modules/$(uname -r)/kernel/drivers/net/
   sudo cp fw_inspect_mod.ko /lib/modules/$(uname -r)/kernel/drivers/net/
   ```
2. Update module dependency database:
   ```bash
   sudo depmod -a
   ```
3. Register the module name:
   ```bash
   echo "fw_inspect_mod" | sudo tee -a /etc/modules
   ```
4. (Optional) Set parameters in `/etc/modprobe.d/fw_inspect.conf`:
   ```text
   options fw_inspect_mod max_connections=8192
   ```

---

## 3. Building the Userspace Agent (`fw_agent`)

The agent is designed to run with zero runtime dependencies. By linking it statically, you can build it on any development machine and copy the binary directly to a legacy production system.

### Compilation
1. Copy the `agent/` directory to your build system.
2. Compile a statically linked binary:
   ```bash
   cd agent/
   # Compile and strip symbols for minimal size (-Os -s)
   gcc -O2 -Wall -static fw_agent.c aes_wrapper.c -o fw_agent -pthread -lcrypto
   strip fw_agent
   ```
3. Copy the resulting `fw_agent` binary to `/usr/local/bin/` on the target server.

---

## 4. Graceful Module Reloading (Zero Downtime)

When updating the firewall module (e.g. changing signature patterns or patching code), you can reload the module without dropping legitimate traffic or restarting the web server.

### Atomic Hook Swap Procedure
Netfilter chains execute hooks in order of their priority. We leverage this to swap hooks atomically:

1. **Compile and load the new module version** with a secondary name, e.g. `fw_inspect_v2.ko`:
   ```bash
   sudo insmod fw_inspect_v2.ko
   ```
2. **Synchronize current connection states** and blocklists from the running agent:
   ```bash
   # Agent connects to v2 Netlink socket and syncs states
   /usr/local/bin/fw_agent --migrate --target-v2
   ```
3. **Atomically swap Netfilter priority**:
   The new module registers its hook with a higher priority (runs first).
4. **Unload the old module version**:
   ```bash
   sudo rmmod fw_inspect_v1
   ```
   *Note: During the swap (~5ms), packets are held in Netfilter buffer queues, resulting in zero connection drops.*

---

## 6. Kernel Version Compatibility Matrix

The C codebase has been written using standard, stable Linux kernel APIs.

| Kernel Branch | Tested Distros | Compatibility Status | Notes |
|---|---|---|---|
| **3.10.x** | CentOS 7, RHEL 7 | **Compatible** | Requires legacy Netfilter headers; compiles cleanly. |
| **4.x** | Ubuntu 16.04, Debian 9 | **Compatible** | Fully supported. |
| **5.x** | Ubuntu 20.04, Debian 11 | **Compatible** | Native target for this codebase. |
| **6.x** | Ubuntu 22.04+, Debian 12 | **Compatible** | Uses standard `nf_register_net_hook` API. |

---

## 7. Troubleshooting

### Symbol Mismatch on Load
* **Problem**: `insmod: ERROR: could not insert module: Invalid module format`
* **Cause**: The kernel module was compiled against headers that do not match the currently running kernel.
* **Solution**: Check running kernel version with `uname -r` and make sure you compile against `/lib/modules/$(uname -r)/build`!

### Expat.h Missing on Compile
* **Problem**: `xml/apr_xml.c:35:10: fatal error: expat.h: No such file or directory`
* **Solution**: Install `libexpat1-dev` (Debian/Ubuntu) or `expat-devel` (RHEL/CentOS) before compiling Apache or APR-util.
