#!/usr/bin/env python3

"""Load YARA rule files uploaded or deleted on another replica.

The replica that handles an upload or a delete swaps its rules at once; this
brings the others in line. Cheap when nothing changed: one query of file names
and sources, compared with the fingerprint of what this process loaded.
"""

import custom_rules
from logger import get_app_logger

TASK_CONFIG = {
    "name": "reload-custom-rules",
    "enabled": True,
    "run_when_loaded": False,
    "interval_seconds": 30,
}


def main():
    try:
        custom_rules.reload_if_changed()
    except Exception as exc:
        get_app_logger().error(f"[Rules] Could not reload uploaded YARA rules: {exc}")
