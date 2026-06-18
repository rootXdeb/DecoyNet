"""
Converts session records into a NumPy feature matrix for ML models.
"""

import numpy as np


FEATURE_COLS = [
    "command_count", "recon_count", "lateral_count",
    "exploit_count", "exfil_count", "mean_delay",
    "stdev_delay", "mean_inter",
]


def sessions_to_matrix(sessions: list[dict]) -> np.ndarray:
    """Convert a list of session dicts to a float32 matrix."""
    rows = []
    for s in sessions:
        rows.append([float(s.get(col, 0)) for col in FEATURE_COLS])
    return np.array(rows, dtype=np.float32) if rows else np.empty((0, len(FEATURE_COLS)))
