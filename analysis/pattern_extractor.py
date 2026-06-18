"""
Extracts Indicators of Compromise (IOCs) and TTPs from session data.
"""

import re


_URL_RE = re.compile(r'https?://[^\s"\']+')
_IP_RE  = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_HASH_RE = re.compile(r'\b[a-fA-F0-9]{32,64}\b')


class PatternExtractor:
    def extract(self, commands: list[str]) -> dict:
        blob = " ".join(commands)
        return {
            "urls":       _URL_RE.findall(blob),
            "ips":        list(set(_IP_RE.findall(blob))),
            "hashes":     list(set(_HASH_RE.findall(blob))),
            "raw_commands": commands,
        }
