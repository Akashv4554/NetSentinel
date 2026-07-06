"""Service detection abstractions.

This module is intentionally stubbed and reserved for future implementation.
"""

from __future__ import annotations


class ServiceDetector:
    """Placeholder for future service detection logic."""

    def get_service_name(self, port: int) -> str:
        """Return the known service name for a port, if available."""
        raise NotImplementedError("Service detection is not implemented yet")

    def detect_banner(self, host: str, port: int) -> str:
        """Attempt to detect a service banner from a host and port."""
        raise NotImplementedError("Banner detection is not implemented yet")
