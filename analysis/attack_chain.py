"""
Builds an attack chain (ordered sequence of TTPs) from a session's commands.
"""


_STAGE_MAP = {
    frozenset(["whoami","id","uname","hostname","ifconfig","ip"]): "Reconnaissance",
    frozenset(["wget","curl","nc","socat","scp"]):                 "C2 / Download",
    frozenset(["chmod","bash","sh","python","python3","perl"]):    "Execution",
    frozenset(["cat","tar","zip","scp","gzip"]):                   "Exfiltration",
    frozenset(["adduser","useradd","passwd","crontab"]):           "Persistence",
}


class AttackChain:
    def __init__(self, commands: list[str]):
        self.commands = commands

    def build(self) -> list[str]:
        seen_stages: list[str] = []
        for cmd in self.commands:
            base = cmd.strip().split()[0] if cmd.strip() else ""
            for stage_cmds, stage_name in _STAGE_MAP.items():
                if base in stage_cmds and stage_name not in seen_stages:
                    seen_stages.append(stage_name)
        return seen_stages

    def as_string(self) -> str:
        chain = self.build()
        return " → ".join(chain) if chain else "No recognisable attack chain"
