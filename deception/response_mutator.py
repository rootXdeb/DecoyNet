"""
Adds subtle variation to responses so the DecoyNet avoids deterministic
fingerprinting by automated scanners.
"""

import random


class ResponseMutator:
    _NOISE_LINES = [
        "",  # empty — most of the time add nothing
        "",
        "",
        "bash: warning: setlocale: LC_ALL: cannot change locale (en_US.UTF-8)",
        "mesg: ttyname failed: Inappropriate ioctl for device",
    ]

    def mutate(self, response: str) -> str:
        """Occasionally append a plausible noise line."""
        noise = random.choice(self._NOISE_LINES)
        if noise:
            return response + "\n" + noise
        return response
