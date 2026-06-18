#!/bin/bash
# Disables unnecessary system services on the DecoyNet VM.
# Reduces attack surface of the host OS itself.

set -e

SERVICES_TO_DISABLE=(
    "avahi-daemon"
    "cups"
    "bluetooth"
    "ModemManager"
    "snapd"
    "apport"
)

echo "[*] Disabling unnecessary services..."
for svc in "${SERVICES_TO_DISABLE[@]}"; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        systemctl stop    "$svc"
        systemctl disable "$svc"
        echo "[+] Disabled: $svc"
    else
        echo "[i] Not running (skipped): $svc"
    fi
done

echo "[*] Restricting SSH to management use only..."
sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/'       /etc/ssh/sshd_config
sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
systemctl restart sshd && echo "[+] SSH hardened."

echo "[+] Service hardening complete."
