"""Typed data models for the scanner foundation.

These dataclasses represent the domain objects used by the scanner engine and
its supporting components.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from app.scanner.constants import DEFAULT_TIMEOUT


@dataclass(slots=True)
class Host:
    """Represents a scanned target host."""

    hostname: Optional[str] = None
    ipv4: Optional[str] = None
    ipv6: Optional[str] = None
    aliases: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Port:
    """Represents a network port to be scanned."""

    number: int
    protocol: str = "tcp"
    service: Optional[str] = None


@dataclass(slots=True)
class ScanRequest:
    """Represents a scan request submitted to the scanner engine."""

    target: Host
    ports: list[Port]
    timeout: float = DEFAULT_TIMEOUT
    thread_count: int = 1


@dataclass(slots=True)
class ScanResult:
    """Represents the outcome of a single scan operation."""

    host: str = ""
    port: int = 0
    protocol: str = "tcp"
    status: str = "pending"
    response_time: Optional[float] = None
    service_name: str = "Unknown"
    error_message: Optional[str] = None
    timestamp: Optional[str] = None
    request: Optional[ScanRequest] = None
    error: Optional[str] = None
    opened_ports: list[Port] = field(default_factory=list)


@dataclass(slots=True)
class HostInformation:
    """Represents collected information about a scanned host."""

    host: Host
    resolved_ipv4: Optional[str] = None
    resolved_ipv6: Optional[str] = None
    is_reachable: bool = False
    services: list[str] = field(default_factory=list)
