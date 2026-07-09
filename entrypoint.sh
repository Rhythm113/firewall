#!/bin/bash
set -e

echo "[entrypoint] Setting up Apache httpd configuration for CGI execution..."
# Enable cgid module for CGI execution in threaded MPM
sed -i 's/#LoadModule cgid_module/LoadModule cgid_module/' /usr/local/apache2/conf/httpd.conf

# Allow ExecCGI inside cgi-bin directory
sed -i '/<Directory "\/usr\/local\/apache2\/cgi-bin">/,/<\/Directory>/ s/Options None/Options +ExecCGI/' /usr/local/apache2/conf/httpd.conf

# Add Handler for python script execution
if ! grep -q "AddHandler cgi-script .py" /usr/local/apache2/conf/httpd.conf; then
    echo "AddHandler cgi-script .py" >> /usr/local/apache2/conf/httpd.conf
fi

echo "[entrypoint] Setting up Netfilter iptables rules for NFQUEUE..."
# Intercept incoming port 80 (HTTP) traffic and send it to NFQUEUE queue 0
iptables -A INPUT -p tcp --dport 80 -j NFQUEUE --queue-num 0

echo "[entrypoint] Generating PGP key pair for agent if not exists..."
if [ ! -d "/root/.gnupg" ] || [ ! -f "/root/.gnupg/pubring.kbx" ]; then
    mkdir -p /root/.gnupg
    chmod 700 /root/.gnupg
    
    cat <<EOF > /tmp/gpg_agent_gen.conf
Key-Type: RSA
Key-Length: 2048
Subkey-Type: RSA
Subkey-Length: 2048
Name-Real: Agent
Name-Email: agent@soc.local
Expire-Date: 0
%no-protection
%commit
EOF

    gpg --batch --generate-key /tmp/gpg_agent_gen.conf
    rm /tmp/gpg_agent_gen.conf
    echo "[entrypoint] Agent PGP key pair generated successfully."
fi

# Import the SOC Server's public key (placed via volume mount)
if [ -f "/etc/fw_keys/soc_pubkey.asc" ]; then
    echo "[entrypoint] Importing SOC Server public key..."
    gpg --import /etc/fw_keys/soc_pubkey.asc
fi

# Export Agent's public key so the SOC can import it if needed
mkdir -p /etc/fw_keys
gpg --armor --export agent@soc.local > /etc/fw_keys/agent_pubkey.asc
echo "[entrypoint] Agent public key exported to /etc/fw_keys/agent_pubkey.asc"

# Create a default YARA rule file so the engine starts cleanly
mkdir -p /etc/fw_inspect/yara
if [ ! -f "/etc/fw_inspect/yara/rules.yar" ]; then
    echo "rule php_webshell { strings: \$a = \"eval(\" \$b = \"system(\" condition: any of them }" > /etc/fw_inspect/yara/rules.yar
fi

echo "[entrypoint] Starting Userspace NFQUEUE Firewall Daemon (fw_nfq) in the background..."
/usr/local/bin/fw_nfq > /var/log/fw_nfq.log 2>&1 &

echo "[entrypoint] Starting Userspace Agent (fw_agent) in the background..."
sleep 1
/usr/local/bin/fw_agent > /var/log/fw_agent.log 2>&1 &

echo "[entrypoint] Starting Apache HTTP Server in the foreground..."
exec httpd -D FOREGROUND
