#!/bin/bash
set -e

echo "[entrypoint] Setting up GnuPG for SOC Server..."
mkdir -p /root/.gnupg
chmod 700 /root/.gnupg

# Generate SOC keypair if it doesn't exist
if [ ! -f "/etc/keys/soc_privkey.asc" ]; then
    echo "[entrypoint] Generating SOC PGP key pair..."
    
    cat <<EOF > /tmp/gpg_soc_gen.conf
Key-Type: RSA
Key-Length: 2048
Subkey-Type: RSA
Subkey-Length: 2048
Name-Real: SOC Server
Name-Email: soc@soc.local
Expire-Date: 0
%no-protection
%commit
EOF

    gpg --batch --generate-key /tmp/gpg_soc_gen.conf
    rm /tmp/gpg_soc_gen.conf

    # Export keys to mounted volume for sharing / backup
    mkdir -p /etc/keys/agent1 /etc/keys/agent2
    gpg --armor --export soc@soc.local > /etc/keys/soc_pubkey.asc
    gpg --armor --export-secret-keys soc@soc.local > /etc/keys/soc_privkey.asc
    
    # Replicate public key into agent subdirectories for container volume mapping
    cp /etc/keys/soc_pubkey.asc /etc/keys/agent1/soc_pubkey.asc
    cp /etc/keys/soc_pubkey.asc /etc/keys/agent2/soc_pubkey.asc
    echo "[entrypoint] SOC public key exported to /etc/keys/soc_pubkey.asc"
else
    echo "[entrypoint] Found existing SOC keys. Importing..."
    gpg --import /etc/keys/soc_privkey.asc
    mkdir -p /etc/keys/agent1 /etc/keys/agent2
    cp /etc/keys/soc_pubkey.asc /etc/keys/agent1/soc_pubkey.asc
    cp /etc/keys/soc_pubkey.asc /etc/keys/agent2/soc_pubkey.asc
fi

# Background daemon to watch and import agent public keys
watch_agent_keys() {
    echo "[watcher] Starting agent PGP key watcher..."
    LAST_HASH=""
    while true; do
        # Calculate combined hash of all public keys in directory tree
        CURRENT_HASH=$(find /etc/keys -name "*.asc" -type f | sort | xargs sha256sum 2>/dev/null | sha256sum | awk '{print $1}')
        if [ "$CURRENT_HASH" != "$LAST_HASH" ]; then
            echo "[watcher] Found new or updated agent public keys. Importing..."
            find /etc/keys -name "*.asc" -type f -exec gpg --import {} + 2>/dev/null
            LAST_HASH="$CURRENT_HASH"
        fi
        sleep 5
    done
}
watch_agent_keys &

echo "[entrypoint] Launching SOC Receiver C Daemon in background..."
./soc_receiver > /var/log/soc_receiver.log 2>&1 &

echo "[entrypoint] Launching Java Spring Boot SOC Console in foreground..."
exec java -jar dashboard.jar
