"""
Generates and persists the SSH server host key.
"""

import os
import logging

logger = logging.getLogger(__name__)
KEY_PATH = os.path.join(os.path.dirname(__file__), "..", "logs", "server_rsa.key")


def get_host_key():
    try:
        import paramiko
    except ImportError:
        return None

    os.makedirs(os.path.dirname(KEY_PATH), exist_ok=True)
    if os.path.exists(KEY_PATH):
        key = paramiko.RSAKey(filename=KEY_PATH)
        logger.debug("Loaded existing host key.")
    else:
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(KEY_PATH)
        logger.info("Generated new RSA host key.")
    return key
