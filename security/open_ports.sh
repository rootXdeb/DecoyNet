#!/bin/bash
# Opens all DecoyNet ports on the firewall
# Run once: sudo bash security/open_ports.sh

echo "[*] Opening DecoyNet ports..."

sudo ufw allow 2222/tcp  comment "SSH DecoyNet"
sudo ufw allow 8080/tcp  comment "HTTP DecoyNet"
sudo ufw allow 2121/tcp  comment "FTP DecoyNet"
sudo ufw allow 2323/tcp  comment "Telnet DecoyNet"
sudo ufw allow 3306/tcp  comment "MySQL DecoyNet"
sudo ufw allow 6379/tcp  comment "Redis DecoyNet"
sudo ufw allow 2525/tcp  comment "SMTP DecoyNet"
sudo ufw allow 3389/tcp  comment "RDP DecoyNet"
sudo ufw allow 4445/tcp  comment "SMB DecoyNet"
sudo ufw allow 27017/tcp comment "MongoDB DecoyNet"
sudo ufw allow 9200/tcp  comment "Elasticsearch DecoyNet"
sudo ufw allow 5900/tcp  comment "VNC DecoyNet"
sudo ufw allow 5432/tcp  comment "PostgreSQL DecoyNet"
sudo ufw allow 3890/tcp  comment "LDAP DecoyNet"
sudo ufw allow 11211/tcp comment "Memcached DecoyNet"
sudo ufw allow 5060/tcp  comment "SIP DecoyNet"
sudo ufw allow 5000/tcp  comment "Dashboard (restrict in prod)"

sudo ufw --force enable
echo "[+] Done. Ports open:"
sudo ufw status | grep -E "2222|8080|2121|2323|3306|6379|2525|3389|4445|27017|9200|5900|5432|3890|11211|5060|5000"
