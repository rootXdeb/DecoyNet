"""
Validates records from external threat feeds before they enter the KB.
"""

import re

_IP_RE  = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
_URL_RE = re.compile(r'^https?://')


class FeedValidator:
    def validate(self, record: dict) -> bool:
        ip  = record.get("ip", "")
        url = record.get("url", "")
        if ip  and not _IP_RE.match(ip):
            return False
        if url and not _URL_RE.match(url):
            return False
        conf = record.get("confidence", 0)
        if not isinstance(conf, (int, float)) or conf < 0 or conf > 100:
            return False
        return True
