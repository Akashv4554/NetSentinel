"""
Banner grabbing utilities for NetSentinel.
"""

from __future__ import annotations

import socket


class BannerGrabber:
    """Attempts to retrieve a banner from an open TCP port."""

    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout

    def grab_banner(self, host: str, port: int) -> str | None:
        """
        Connect to an open TCP port and return its banner.

        Args:
            host: Target hostname/IP
            port: Open TCP port

        Returns:
            Banner string if available, otherwise None.
        """

        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:

                sock.settimeout(self.timeout)

                # Some services immediately send a banner
                try:
                    banner = sock.recv(4096).decode(
                        errors="ignore"
                    ).strip()

                    if banner:
                        return banner

                except socket.timeout:
                    pass

                # Trigger HTTP servers
                if port in (80, 8080, 8000, 443):

                    request = (
                        f"HEAD / HTTP/1.1\r\n"
                        f"Host: {host}\r\n"
                        "Connection: close\r\n\r\n"
                    )

                    sock.sendall(request.encode())

                    response = sock.recv(4096).decode(
                        errors="ignore"
                    )

                    return response.strip()

        except Exception:
            return None

        return None