"""
Simulates a realistic bash shell environment.
"""

import random

_HOSTNAMES = ["web-prod-01", "db-server-02", "api-gateway", "fileserver-03"]
_USERS     = ["root", "admin", "ubuntu", "www-data"]


class FakeShell:
    def __init__(self):
        self.hostname = random.choice(_HOSTNAMES)
        self.user     = random.choice(_USERS)
        self.cwd      = "/root" if self.user == "root" else f"/home/{self.user}"
        self.env      = {
            "HOME": self.cwd, "USER": self.user,
            "SHELL": "/bin/bash", "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        }

    def prompt(self) -> str:
        symbol = "#" if self.user == "root" else "$"
        return f"{self.user}@{self.hostname}:{self.cwd}{symbol} "

    def change_dir(self, path: str) -> str:
        if path in ("~", ""):
            self.cwd = self.env["HOME"]
            return ""
        if path.startswith("/"):
            self.cwd = path
        else:
            self.cwd = self.cwd.rstrip("/") + "/" + path
        return ""
