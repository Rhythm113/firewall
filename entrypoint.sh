#!/bin/bash
set -e

echo "[entrypoint] Setting up Apache httpd configuration for PHP-FPM proxying..."
# Enable proxy and proxy_fcgi modules
sed -i 's/#LoadModule proxy_module/LoadModule proxy_module/' /usr/local/apache2/conf/httpd.conf
sed -i 's/#LoadModule proxy_fcgi_module/LoadModule proxy_fcgi_module/' /usr/local/apache2/conf/httpd.conf

# Add Handler for PHP-FPM UNIX socket proxying
if ! grep -q "SetHandler \"proxy:unix:/run/php/php7.4-fpm.sock|fcgi://localhost\"" /usr/local/apache2/conf/httpd.conf; then
    cat <<EOF >> /usr/local/apache2/conf/httpd.conf
<FilesMatch \.php$>
    SetHandler "proxy:unix:/run/php/php7.4-fpm.sock|fcgi://localhost"
</FilesMatch>
EOF
fi

# Set DirectoryIndex to support index.php
sed -i 's/DirectoryIndex index.html/DirectoryIndex index.php index.html/' /usr/local/apache2/conf/httpd.conf

# Ensure PHP-FPM socket directory exists
mkdir -p /run/php

# Ensure upload directory exists and has correct permissions for www-data
UPLOAD_DIR_PATH=${UPLOAD_DIR:-/var/www/uploads}
mkdir -p "$UPLOAD_DIR_PATH"
chown -R www-data:www-data "$UPLOAD_DIR_PATH"
chmod 777 "$UPLOAD_DIR_PATH"

echo "[entrypoint] Starting PHP-FPM daemon..."
/usr/sbin/php-fpm7.4 -D


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
