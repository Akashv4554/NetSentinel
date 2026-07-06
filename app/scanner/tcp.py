"""TCP scanning abstractions.

This module defines the TCP scanner interface and intentionally leaves all
implementation details unimplemented for future work.
"""

from __future__ import annotations


class TCPScanner:
    """Placeholder for future TCP scanning logic."""

    def connect(self, host: str, port: int) -> None:
        """Establish a TCP connection to a host and port."""
        raise NotImplementedError("TCP scanning is not implemented yet")

    def scan_port(self, host: str, port: int) -> None:
        """Scan a single TCP port."""
        raise NotImplementedError("TCP scanning is not implemented yet")

    def scan_range(self, host: str, start_port: int, end_port: int) -> None:
        """Scan a TCP port range."""
        raise NotImplementedError("TCP scanning is not implemented yet")
