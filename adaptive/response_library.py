"""
ResponseLibrary — provides strategy-aware file content and directory listings.

The same file path returns DIFFERENT content depending on the current strategy.
This is what makes the deception genuinely adaptive — the system decides
how much to reveal based on who it thinks is asking.
"""

import random
import time
from adaptive.strategy_engine import Strategy


class ResponseLibrary:
    """
    Returns appropriate responses based on current deception strategy.
    Called by FakeFilesystem to vary content depth.
    """

    def get_file_content(self, path: str, strategy: Strategy) -> str:
        """Return file content appropriate for the current strategy."""
        handlers = {
            "/etc/passwd":              self._etc_passwd,
            "/etc/shadow":              self._etc_shadow,
            "/etc/hosts":               self._etc_hosts,
            "/root/.bash_history":      self._bash_history,
            "/root/notes.txt":          self._notes_txt,
            "/root/.ssh/id_rsa":        self._id_rsa,
            "/root/.aws/credentials":   self._aws_credentials,
            "/var/www/html/.env":       self._dotenv,
            "/var/www/html/config.php": self._config_php,
            "/var/www/html/wp-config.php": self._wp_config,
            "/opt/app/config.py":       self._app_config,
            "/root/backup.sql":         self._backup_sql,
            "/etc/crontab":             self._crontab,
            "/proc/version":            self._proc_version,
            "/etc/ssh/sshd_config":     self._sshd_config,
        }

        handler = handlers.get(path)
        if handler:
            return handler(strategy)
        return f"cat: {path}: No such file or directory"

    # ── File content handlers ─────────────────────────────────────────────────

    def _etc_passwd(self, strategy: Strategy) -> str:
        base = (
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
            "mysql:x:111:114:MySQL Server:/var/lib/mysql:/bin/false\n"
            "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n"
        )
        if strategy in (Strategy.ENGAGE, Strategy.TRAP):
            base += (
                "deploy:x:1001:1001:Deploy User:/home/deploy:/bin/bash\n"
                "admin:x:1002:1002:Admin:/home/admin:/bin/bash\n"
                "backup:x:1003:1003:Backup:/home/backup:/bin/sh\n"
                "devops:x:1004:1004:DevOps:/home/devops:/bin/bash\n"
            )
        return base

    def _etc_shadow(self, strategy: Strategy) -> str:
        if strategy == Strategy.DEFLECT:
            return "cat: /etc/shadow: Permission denied"
        base = (
            "root:$6$rounds=5000$saltsalt$FakeHashForRoot000000000000000000000000000000000000000000000000000000000000000000000:19000:0:99999:7:::\n"
            "ubuntu:$6$rounds=5000$saltsalt$FakeHashForUbuntu00000000000000000000000000000000000000000000000000000000000000000:19000:0:99999:7:::\n"
        )
        if strategy in (Strategy.ENGAGE, Strategy.TRAP):
            base += (
                "admin:$6$rounds=5000$saltsalt$FakeHashForAdmin000000000000000000000000000000000000000000000000000000000000000:19000:0:99999:7:::\n"
                "deploy:$6$rounds=5000$saltsalt$FakeHashForDeploy00000000000000000000000000000000000000000000000000000000000000:19000:0:99999:7:::\n"
            )
        return base

    def _etc_hosts(self, strategy: Strategy) -> str:
        base = (
            "127.0.0.1 localhost\n"
            "127.0.1.1 web-prod-01\n"
            "::1 localhost ip6-localhost ip6-loopback\n"
        )
        if strategy in (Strategy.ENGAGE, Strategy.TRAP):
            # Leak internal network topology as bait
            base += (
                "\n# Internal network\n"
                "10.0.0.10 db-primary.internal\n"
                "10.0.0.11 db-replica.internal\n"
                "10.0.0.20 redis-cache.internal\n"
                "10.0.0.30 api-gateway.internal\n"
                "10.0.0.40 admin-panel.internal\n"
                "10.0.0.50 backup-server.internal\n"
            )
        return base

    def _bash_history(self, strategy: Strategy) -> str:
        base = [
            "ls -la", "cd /var/www/html", "cat .env",
            "ps aux", "netstat -an", "df -h", "free -m",
        ]
        if strategy in (Strategy.ENGAGE, Strategy.TRAP):
            base += [
                "mysql -u root -p'Pr0d@DB_2024!' corp_production",
                "ssh deploy@10.0.0.50 'tar -czf /backups/$(date +%Y%m%d).tar.gz /var/www'",
                "cat /root/.aws/credentials",
                "aws s3 ls s3://corp-backups-prod/",
                "kubectl get pods --all-namespaces",
                "cat /etc/shadow",
                "crontab -e",
                "cd /opt/app && python3 manage.py shell",
                "grep -r 'password' /var/www/html/ --include='*.php'",
            ]
        return "\n".join(base)

    def _notes_txt(self, strategy: Strategy) -> str:
        if strategy == Strategy.DEFLECT:
            return "TODO list\n- Update server\n"
        base = (
            "Server maintenance notes\n"
            "========================\n"
            "- Apache restart: systemctl restart apache2\n"
            "- MySQL root: see keepass vault\n"
        )
        if strategy in (Strategy.ENGAGE, Strategy.TRAP):
            base += (
                "\nCREDENTIALS (move to vault ASAP)\n"
                "---------------------------------\n"
                "MySQL root:   Pr0d@DB_2024!\n"
                "Redis auth:   r3d1s_s3cr3t_2024\n"
                "Deploy SSH:   see /root/.ssh/id_rsa (no passphrase)\n"
                "AWS key:      AKIAFAKE00000000PROD1 / FakeSecretKey/PROD\n"
                "\nTODO: rotate all credentials after incident!\n"
            )
        return base

    def _id_rsa(self, strategy: Strategy) -> str:
        if strategy in (Strategy.OBSERVE, Strategy.DEFLECT):
            return "cat: /root/.ssh/id_rsa: Permission denied"
        # Fake RSA private key structure — NOT a real key
        return (
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            "b3BlbnNzaC1rZXktdjEAAAAAbmMKYXBlcy0yNTYtY2JjAAAABmJjcnlwdAAAABAAAA\n"
            "ABAAAAFAKEKEY000000000000000000000000000000000000000000000000000000\n"
            "FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE\n"
            "FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE\n"
            "FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE\n"
            "AAAAA\n"
            "-----END OPENSSH PRIVATE KEY-----\n"
        )

    def _aws_credentials(self, strategy: Strategy) -> str:
        if strategy == Strategy.DEFLECT:
            return "cat: /root/.aws/credentials: No such file or directory"
        if strategy == Strategy.OBSERVE:
            return "cat: /root/.aws/credentials: Permission denied"
        return (
            "[default]\n"
            "aws_access_key_id = AKIAFAKE00000000PROD1\n"
            "aws_secret_access_key = FakeSecretKey/PROD/2024/xxxxxxxxxxxxxxxxxxx\n"
            "region = us-east-1\n"
            "\n[backup]\n"
            "aws_access_key_id = AKIAFAKE00000000BAK01\n"
            "aws_secret_access_key = FakeSecretKey/BACKUP/2024/xxxxxxxxxxxxxxxxx\n"
        )

    def _dotenv(self, strategy: Strategy) -> str:
        base = (
            "APP_ENV=production\n"
            "APP_DEBUG=false\n"
        )
        if strategy in (Strategy.ENGAGE, Strategy.TRAP):
            base += (
                "APP_KEY=base64:FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE==\n"
                "DB_CONNECTION=mysql\n"
                "DB_HOST=10.0.0.10\n"
                "DB_PORT=3306\n"
                "DB_DATABASE=corp_production\n"
                "DB_USERNAME=app_user\n"
                "DB_PASSWORD=Pr0dAppP@ss2024!\n"
                "REDIS_HOST=10.0.0.20\n"
                "REDIS_PASSWORD=r3d1s_s3cr3t_2024\n"
                "STRIPE_SECRET=sk_live_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE\n"
                "AWS_ACCESS_KEY_ID=AKIAFAKE00000000PROD1\n"
                "AWS_SECRET_ACCESS_KEY=FakeSecretKey/PROD/2024/xxxxxxxxxxxxxxxxxxx\n"
                "MAIL_PASSWORD=smtp_fake_password_2024\n"
            )
        return base

    def _config_php(self, strategy: Strategy) -> str:
        if strategy in (Strategy.ENGAGE, Strategy.TRAP):
            return (
                "<?php\n"
                "define('DB_HOST',     '10.0.0.10');\n"
                "define('DB_NAME',     'corp_production');\n"
                "define('DB_USER',     'app_user');\n"
                "define('DB_PASSWORD', 'Pr0dAppP@ss2024!');\n"
                "define('ADMIN_EMAIL', 'admin@corp.internal');\n"
                "define('SECRET_KEY',  'FakeSecretKey_ABCDEFGHIJKLMNOP');\n"
                "?>\n"
            )
        return "<?php\n// Configuration\n?>\n"

    def _wp_config(self, strategy: Strategy) -> str:
        if strategy in (Strategy.ENGAGE, Strategy.TRAP):
            return (
                "<?php\n"
                "define('DB_NAME',     'wordpress_prod');\n"
                "define('DB_USER',     'wp_user');\n"
                "define('DB_PASSWORD', 'WpPr0d@2024!');\n"
                "define('DB_HOST',     '10.0.0.10');\n"
                "define('AUTH_KEY',    'FAKE-AUTH-KEY-ABCDEFGHIJKLMNOPQRSTUVWXYZ');\n"
                "define('SECURE_AUTH_KEY', 'FAKE-SECURE-KEY-ABCDEFGHIJKLMNOPQR');\n"
                "$table_prefix = 'wp_';\n"
                "?>\n"
            )
        return "<?php\n// WordPress configuration\n?>\n"

    def _app_config(self, strategy: Strategy) -> str:
        if strategy in (Strategy.ENGAGE, Strategy.TRAP):
            return (
                "# Application configuration\n"
                "DATABASE_URL = 'postgresql://app_user:Pr0dAppP@ss2024!@10.0.0.10/corp_db'\n"
                "SECRET_KEY   = 'django-insecure-FAKE-SECRET-KEY-ABCDEFGHIJKLMNOP'\n"
                "DEBUG        = False\n"
                "ALLOWED_HOSTS = ['*']\n"
                "AWS_KEY      = 'AKIAFAKE00000000PROD1'\n"
                "AWS_SECRET   = 'FakeSecretKey/PROD/2024/xxxxxxxxxxxxxxxxxxx'\n"
            )
        return "# Application configuration\nDEBUG = False\n"

    def _backup_sql(self, strategy: Strategy) -> str:
        if strategy != Strategy.TRAP:
            return "cat: /root/backup.sql: Permission denied"
        return (
            "-- MySQL dump 10.13  Distrib 8.0.33\n"
            "-- Host: 10.0.0.10    Database: corp_production\n"
            "-- Date: " + time.strftime("%Y-%m-%d %H:%M:%S") + "\n\n"
            "CREATE TABLE users (\n"
            "  id INT PRIMARY KEY AUTO_INCREMENT,\n"
            "  email VARCHAR(255),\n"
            "  password_hash VARCHAR(255),\n"
            "  role VARCHAR(50),\n"
            "  api_key VARCHAR(64)\n"
            ");\n\n"
            "INSERT INTO users VALUES\n"
            "(1,'ceo@corp.com','$2b$12$FAKEHASH001','admin','sk-FAKE-API-KEY-CEO-001'),\n"
            "(2,'cto@corp.com','$2b$12$FAKEHASH002','admin','sk-FAKE-API-KEY-CTO-002'),\n"
            "(3,'dev@corp.com','$2b$12$FAKEHASH003','developer','sk-FAKE-API-KEY-DEV-003');\n"
        )

    def _crontab(self, strategy: Strategy) -> str:
        base = (
            "# /etc/crontab\n"
            "SHELL=/bin/sh\n"
            "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n\n"
            "17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly\n"
            "25 6    * * *   root    test -x /usr/sbin/anacron || ...\n"
        )
        if strategy in (Strategy.ENGAGE, Strategy.TRAP):
            base += (
                "\n# Custom jobs\n"
                "*/5 * * * * root /opt/scripts/health_check.sh\n"
                "0 2 * * * root /root/backup_db.sh >> /var/log/backup.log 2>&1\n"
                "30 3 * * 0 root tar -czf /backups/weekly_$(date +\\%Y\\%m\\%d).tar.gz /var/www/html\n"
            )
        return base

    def _proc_version(self, strategy: Strategy) -> str:
        return "Linux version 5.15.0-76-generic (buildd@lcy02-amd64-016) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #83-Ubuntu SMP Thu Jun 15 19:16:32 UTC 2023\n"

    def _sshd_config(self, strategy: Strategy) -> str:
        return (
            "Port 22\n"
            "PermitRootLogin yes\n"
            "PasswordAuthentication yes\n"
            "MaxAuthTries 6\n"
            "PubkeyAuthentication yes\n"
        )
