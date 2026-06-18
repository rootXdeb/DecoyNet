#!/bin/bash
# Firewall hardening — UFW rules for the DecoyNet VM.
# Run once as root after OS install.

set -e

echo "[*] Resetting UFW to defaults..."
ufw --force reset

echo "[*] Setting default policies..."
ufw default deny incoming
ufw default allow outgoing

echo "[*] Allowing DecoyNet ports..."
ufw allow 2222/tcp   comment "Fake SSH DecoyNet"
ufw allow 8080/tcp   comment "Fake HTTP DecoyNet"
ufw allow 5000/tcp   comment "Dashboard (restrict to management IP in prod)"

echo "[*] Enabling UFW..."
ufw --force enable

echo "[+] Firewall rules applied:"
ufw status verbose
