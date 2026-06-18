#!/bin/bash
# Creates a dedicated non-root user to run the DecoyNet process.
# Principle of least privilege — the process never runs as root.

set -e

DECOYNET_USER="DecoyNet"
DECOYNET_DIR="/opt/DecoyNet_platform"

echo "[*] Creating system user: $DECOYNET_USER"
if id "$DECOYNET_USER" &>/dev/null; then
    echo "[i] User already exists — skipping."
else
    useradd --system --no-create-home --shell /usr/sbin/nologin "$DECOYNET_USER"
    echo "[+] User '$DECOYNET_USER' created."
fi

echo "[*] Setting ownership on $DECOYNET_DIR ..."
mkdir -p "$DECOYNET_DIR"
chown -R "$DECOYNET_USER":"$DECOYNET_USER" "$DECOYNET_DIR"
chmod 750 "$DECOYNET_DIR"

echo "[+] User setup complete. Run DecoyNet as: sudo -u $DECOYNET_USER python3 main.py"
