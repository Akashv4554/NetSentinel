"""Reusable validation helpers for scanner inputs.

The validation utilities provide descriptive exceptions for network-oriented
values such as IP addresses, hostnames, ports, and port ranges.
"""

from __future__ import annotations

import ipaddress
from typing import Final

from app.scanner.constants import MAX_PORT, MIN_PORT


class ValidationError(ValueError):
    """Base exception for scanner input validation errors."""


class IPv4ValidationError(ValidationError):
    """Raised when an IPv4 address is invalid."""


class IPv6ValidationError(ValidationError):
    """Raised when an IPv6 address is invalid."""


class HostnameValidationError(ValidationError):
    """Raised when a hostname is invalid."""


class PortValidationError(ValidationError):
    """Raised when a port number is invalid."""


class PortRangeValidationError(ValidationError):
    """Raised when a port range is invalid."""


class ProtocolValidationError(ValidationError):
    """Raised when a protocol value is invalid."""


def validate_ipv4(value: str) -> str:
    """Validate and normalize an IPv4 address."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:  # pragma: no cover - defensive branch
        raise IPv4ValidationError(f"Invalid IPv4 address: {value}") from exc

    if not isinstance(address, ipaddress.IPv4Address):
        raise IPv4ValidationError(f"Expected IPv4 address, got: {value}")

    return str(address)


def validate_ipv6(value: str) -> str:
    """Validate and normalize an IPv6 address."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:  # pragma: no cover - defensive branch
        raise IPv6ValidationError(f"Invalid IPv6 address: {value}") from exc

    if not isinstance(address, ipaddress.IPv6Address):
        raise IPv6ValidationError(f"Expected IPv6 address, got: {value}")

    return str(address)


def validate_hostname(value: str) -> str:
    """Validate a DNS hostname using basic RFC-like checks."""
    if not value or not value.strip():
        raise HostnameValidationError("Hostname cannot be empty")

    if value.endswith("."):
        value = value[:-1]

    labels = value.split(".")
    if len(labels) > 1 and any(not label for label in labels):
        raise HostnameValidationError(f"Hostname contains an empty label: {value}")

    for label in labels:
        if len(label) > 63:
            raise HostnameValidationError(f"Hostname label is too long: {label}")
        if not label.isalnum() and "-" not in label:
            raise HostnameValidationError(f"Invalid hostname label: {label}")

    return value


def validate_port_number(value: int) -> int:
    """Validate that a port number falls within the valid range."""
    if not isinstance(value, int):
        raise PortValidationError(f"Port must be an integer, got {type(value).__name__}")

    if value < MIN_PORT or value > MAX_PORT:
        raise PortValidationError(
            f"Port must be between {MIN_PORT} and {MAX_PORT}, got {value}"
        )

    return value


def validate_port_range(start_port: int, end_port: int) -> tuple[int, int]:
    """Validate a port range and ensure the start is not greater than the end."""
    start = validate_port_number(start_port)
    end = validate_port_number(end_port)

    if start > end:
        raise PortRangeValidationError(
            f"Start port {start} cannot be greater than end port {end}"
        )

    return start, end
