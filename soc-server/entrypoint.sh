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
    mkdir -p /etc/keys
    gpg --armor --export soc@soc.local > /etc/keys/soc_pubkey.asc
    gpg --armor --export-secret-keys soc@soc.local > /etc/keys/soc_privkey.asc
    echo "[entrypoint] SOC public key exported to /etc/keys/soc_pubkey.asc"
else
    echo "[entrypoint] Found existing SOC keys. Importing..."
    gpg --import /etc/keys/soc_privkey.asc
fi

# Background daemon to watch and import agent public keys
watch_agent_keys() {
    echo "[watcher] Starting agent PGP key watcher..."
    LAST_HASH=""
    while true; do
        if [ -f "/etc/keys/agent_pubkey.asc" ]; then
            CURRENT_HASH=$(sha256sum /etc/keys/agent_pubkey.asc | awk '{print $1}')
            if [ "$CURRENT_HASH" != "$LAST_HASH" ]; then
                echo "[watcher] Found updated agent public key. Importing..."
                gpg --import /etc/keys/agent_pubkey.asc
                LAST_HASH="$CURRENT_HASH"
            fi
        fi
        sleep 5
    done
}
watch_agent_keys &

echo "[entrypoint] Launching SOC Receiver..."
exec ./soc_receiver
