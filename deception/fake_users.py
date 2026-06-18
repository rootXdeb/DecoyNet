"""
Generates fake enterprise user accounts for honey database seeding.
"""

import hashlib, random, time

_FIRST = ["alice", "bob", "charlie", "diana", "eve", "frank", "grace"]
_LAST  = ["smith", "jones", "taylor", "brown", "wilson", "moore"]
_ROLES = ["developer", "sysadmin", "analyst", "devops", "manager"]


def generate_users(count: int = 20) -> list[dict]:
    users = []
    for i in range(count):
        first = random.choice(_FIRST)
        last  = random.choice(_LAST)
        pw    = f"{first}{random.randint(1000,9999)}!"
        users.append({
            "id":       i + 1,
            "username": f"{first}.{last}",
            "email":    f"{first}.{last}@corp.internal",
            "role":     random.choice(_ROLES),
            "pw_hash":  hashlib.sha256(pw.encode()).hexdigest(),
            "created":  int(time.time()) - random.randint(0, 31536000),
        })
    return users
