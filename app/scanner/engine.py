"""Scanner engine foundation.

The scanner engine is intentionally limited to configuration and dependency
injection at this stage. Actual scanning behavior will be implemented later.
"""

from __future__ import annotations

import logging
from typing import Optional

from app.scanner.constants import DEFAULT_THREADS, DEFAULT_TIMEOUT
from app.scanner.tcp import TCPScanner
from app.scanner.udp import UDPScanner


class ScannerEngine:
    """High-level orchestrator for scanner components.

    This class is responsible for wiring dependencies and exposing the shared
    configuration for the networking engine. Concrete scanning methods remain
    as TODOs for future implementation.
    """

    def __init__(
        self,
        timeout: float = DEFAULT_TIMEOUT,
        thread_count: int = DEFAULT_THREADS,
        logger: Optional[logging.Logger] = None,
        tcp_scanner: Optional[TCPScanner] = None,
        udp_scanner: Optional[UDPScanner] = None,
    ) -> None:
        self.timeout = timeout
        self.thread_count = thread_count
        self.logger = logger or logging.getLogger("netsentinel.scanner")
        self.tcp_scanner = tcp_scanner or TCPScanner()
        self.udp_scanner = udp_scanner or UDPScanner()

    def scan(self) -> None:
        """Placeholder for future scan orchestration logic."""
        raise NotImplementedError("Scanning is not implemented yet")
