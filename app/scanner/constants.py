"""Shared constants and configuration defaults for the scanner foundation.

These values are intentionally configurable and should be reused by all
scanner components.
"""

from __future__ import annotations

import os
from typing import Final

DEFAULT_TIMEOUT: Final[float] = float(os.getenv("NETSENTINEL_TIMEOUT", "2.0"))
DEFAULT_THREADS: Final[int] = int(os.getenv("NETSENTINEL_THREADS", "10"))
MAX_PORT: Final[int] = 65535
MIN_PORT: Final[int] = 1
COMMON_PORTS: Final[tuple[int, ...]] = (21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 3306, 8080)
SUPPORTED_PROTOCOLS: Final[tuple[str, ...]] = ("tcp", "udp")
SCAN_STATUS: Final[dict[str, str]] = {
    "PENDING": "pending",
    "RUNNING": "running",
    "SUCCESS": "success",
    "FAILED": "failed",
    "SKIPPED": "skipped",
}
