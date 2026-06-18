"""
Catalogue of planted fake vulnerabilities exposed to lure attackers deeper.
"""

FAKE_VULNS = [
    {"cve": "CVE-2021-44228", "service": "log4j", "path": "/opt/app/lib/log4j-2.14.1.jar",
     "description": "Remote code execution via JNDI injection"},
    {"cve": "CVE-2023-44487", "service": "Apache 2.4.51", "path": "/etc/apache2",
     "description": "HTTP/2 Rapid Reset DoS vulnerability"},
    {"cve": "CVE-2019-0708",  "service": "RDP", "path": None,
     "description": "BlueKeep — unauthenticated RCE in Remote Desktop"},
    {"cve": "CVE-2022-1388",  "service": "F5 BIG-IP", "path": "/mgmt/tm/util/bash",
     "description": "iControl REST auth bypass"},
]


def get_random_vuln() -> dict:
    import random
    return random.choice(FAKE_VULNS)
