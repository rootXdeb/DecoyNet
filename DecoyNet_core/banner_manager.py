"""
Rotates SSH/service banners to make the DecoyNet harder to fingerprint.
"""

import random
import time
from config import BANNER_ROTATION_INTERVAL

_BANNERS = [
    "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n",
    "SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2\r\n",
    "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n",
    "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13\r\n",
    "SSH-2.0-dropbear_2020.81\r\n",
]


class BannerManager:
    _current_banner: str = _BANNERS[0]
    _last_rotation: float = 0.0

    def get_banner(self) -> str:
        now = time.time()
        if now - BannerManager._last_rotation > BANNER_ROTATION_INTERVAL:
            BannerManager._current_banner = random.choice(_BANNERS)
            BannerManager._last_rotation = now
        return BannerManager._current_banner
