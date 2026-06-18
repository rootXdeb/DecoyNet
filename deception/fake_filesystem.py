"""
Strategy-aware fake filesystem.
Directory listings and file contents vary based on current deception strategy.
"""

from adaptive.strategy_engine import Strategy
from adaptive.response_library import ResponseLibrary

_lib = ResponseLibrary()

_DIRS: dict[str, dict] = {
    "/": {
        "short": "bin  boot  dev  etc  home  lib  opt  proc  root  srv  sys  tmp  usr  var",
        "long": (
            "total 68\r\n"
            "drwxr-xr-x  20 root root 4096 Jan  1 00:00 .\r\n"
            "drwxr-xr-x  20 root root 4096 Jan  1 00:00 ..\r\n"
            "drwxr-xr-x   2 root root 4096 Jan  1 00:00 bin\r\n"
            "drwxr-xr-x   3 root root 4096 Jan  1 00:00 etc\r\n"
            "drwxr-xr-x   3 root root 4096 Jan  1 00:00 home\r\n"
            "drwx------   5 root root 4096 Jan  1 00:00 root\r\n"
            "drwxr-xr-x   2 root root 4096 Jan  1 00:00 tmp\r\n"
            "drwxr-xr-x  11 root root 4096 Jan  1 00:00 usr\r\n"
            "drwxr-xr-x  13 root root 4096 Jan  1 00:00 var\r\n"
        ),
    },
    "/root": {
        "short": ".bash_history  .bashrc  .profile  .ssh  notes.txt  backup.sql",
        "long": (
            "total 48\r\n"
            "drwx------  4 root root 4096 Jan  1 00:00 .\r\n"
            "drwxr-xr-x 20 root root 4096 Jan  1 00:00 ..\r\n"
            "-rw-------  1 root root  842 Jan  1 00:00 .bash_history\r\n"
            "-rw-r--r--  1 root root 3526 Jan  1 00:00 .bashrc\r\n"
            "-rw-------  1 root root  207 Jan  1 00:00 .profile\r\n"
            "drwx------  2 root root 4096 Jan  1 00:00 .ssh\r\n"
            "-rw-r--r--  1 root root  312 Jan  1 00:00 notes.txt\r\n"
            "-rw-------  1 root root 148M Jan  1 00:00 backup.sql\r\n"
        ),
    },
    "/root/.ssh": {
        "short": "authorized_keys  id_rsa  id_rsa.pub  known_hosts",
        "long": (
            "total 24\r\n"
            "-rw-------  1 root root  399 Jan  1 00:00 authorized_keys\r\n"
            "-rw-------  1 root root 2655 Jan  1 00:00 id_rsa\r\n"
            "-rw-r--r--  1 root root  572 Jan  1 00:00 id_rsa.pub\r\n"
            "-rw-r--r--  1 root root  884 Jan  1 00:00 known_hosts\r\n"
        ),
    },
    "/root/.aws": {
        "short": "credentials  config",
        "long": (
            "total 8\r\n"
            "-rw-------  1 root root 116 Jan  1 00:00 credentials\r\n"
            "-rw-r--r--  1 root root  29 Jan  1 00:00 config\r\n"
        ),
    },
    "/etc": {
        "short": "passwd  shadow  hosts  hostname  crontab  ssh  nginx  mysql  apt  fstab",
        "long": (
            "total 240\r\n"
            "-rw-r--r--  1 root root   2847 Jan  1 00:00 passwd\r\n"
            "-rw-r-----  1 root shadow 1312 Jan  1 00:00 shadow\r\n"
            "-rw-r--r--  1 root root    221 Jan  1 00:00 hosts\r\n"
            "-rw-r--r--  1 root root     13 Jan  1 00:00 hostname\r\n"
            "-rw-r--r--  1 root root    722 Jan  1 00:00 crontab\r\n"
            "drwxr-xr-x  2 root root   4096 Jan  1 00:00 ssh\r\n"
            "drwxr-xr-x  2 root root   4096 Jan  1 00:00 nginx\r\n"
            "drwxr-xr-x  2 root root   4096 Jan  1 00:00 mysql\r\n"
        ),
    },
    "/var/www/html": {
        "short": "index.php  config.php  wp-config.php  .env  uploads  admin",
        "long": (
            "total 96\r\n"
            "-rw-r--r--  1 www-data www-data   402 Jan  1 00:00 index.php\r\n"
            "-rw-r--r--  1 www-data www-data  1821 Jan  1 00:00 config.php\r\n"
            "-rw-r--r--  1 www-data www-data  3214 Jan  1 00:00 wp-config.php\r\n"
            "-rw-------  1 www-data www-data   892 Jan  1 00:00 .env\r\n"
            "drwxr-xr-x  2 www-data www-data  4096 Jan  1 00:00 uploads\r\n"
            "drwxr-xr-x  2 www-data www-data  4096 Jan  1 00:00 admin\r\n"
        ),
    },
    "/tmp": {
        "short": ".",
        "long": "total 0\r\ndrwxrwxrwt  2 root root 4096 Jan  1 00:00 .\r\n",
    },
    "/opt": {
        "short": "app  scripts  backup",
        "long": (
            "drwxr-xr-x  2 root root 4096 Jan  1 00:00 app\r\n"
            "drwxr-xr-x  2 root root 4096 Jan  1 00:00 scripts\r\n"
            "drwxr-xr-x  2 root root 4096 Jan  1 00:00 backup\r\n"
        ),
    },
}


class FakeFilesystem:
    def listdir_detailed(self, path: str, strategy: Strategy) -> dict:
        path = path.rstrip("/") or "/"
        entry = _DIRS.get(path)
        if not entry:
            return {
                "short": f"ls: cannot access '{path}': No such file or directory",
                "long":  f"ls: cannot access '{path}': No such file or directory",
            }
        if strategy == Strategy.DEFLECT:
            return {"short": ".", "long": "total 0\r\n"}
        return entry

    def listdir(self, path: str) -> str:
        path = path.rstrip("/") or "/"
        return _DIRS.get(path, {}).get("short",
               f"ls: cannot access '{path}': No such file or directory")

    def read_file(self, path: str, strategy: Strategy = Strategy.OBSERVE) -> str:
        return _lib.get_file_content(path, strategy)
