#!/bin/bash
set -e

echo "[entrypoint] Setting up Apache httpd configuration for PHP-FPM proxying..."
# Enable proxy and proxy_fcgi modules
sed -i 's/#LoadModule proxy_module/LoadModule proxy_module/' /usr/local/apache2/conf/httpd.conf
sed -i 's/#LoadModule proxy_fcgi_module/LoadModule proxy_fcgi_module/' /usr/local/apache2/conf/httpd.conf

# Change Apache from the source-build default (daemon) to www-data so it can
# connect to the PHP-FPM socket owned by www-data:www-data
sed -i 's/^User .*/User www-data/' /usr/local/apache2/conf/httpd.conf
sed -i 's/^Group .*/Group www-data/' /usr/local/apache2/conf/httpd.conf

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

# Ensure PHP-FPM pool config allows www-data to access the socket
if [ -f "/etc/php/7.4/fpm/pool.d/www.conf" ]; then
    sed -i 's/^listen.owner =.*/listen.owner = www-data/' /etc/php/7.4/fpm/pool.d/www.conf 2>/dev/null || true
    sed -i 's/^listen.group =.*/listen.group = www-data/' /etc/php/7.4/fpm/pool.d/www.conf 2>/dev/null || true
    sed -i 's/^listen.mode =.*/listen.mode = 0660/' /etc/php/7.4/fpm/pool.d/www.conf 2>/dev/null || true
fi

# Ensure upload directory exists and has correct permissions for www-data
UPLOAD_DIR_PATH=${UPLOAD_DIR:-/var/www/uploads}
mkdir -p "$UPLOAD_DIR_PATH"
chown -R www-data:www-data "$UPLOAD_DIR_PATH"
chmod 777 "$UPLOAD_DIR_PATH"
chown -R www-data:www-data /usr/local/apache2/htdocs

echo "[entrypoint] Starting PHP-FPM daemon..."
/usr/sbin/php-fpm7.4 -D


echo "[entrypoint] Setting up Netfilter iptables rules for NFQUEUE..."
# Intercept incoming port 80 (HTTP) and port 443 (HTTPS) traffic and send it to NFQUEUE queue 0
iptables -A INPUT -p tcp -m multiport --dports 80,443 -j NFQUEUE --queue-num 0

# Ensure /etc/fw_keys directory exists for agent uuid
mkdir -p /etc/fw_keys

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
