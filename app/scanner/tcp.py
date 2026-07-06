"""TCP scanning abstractions.

This module provides the initial one-port TCP scanning implementation for
NetSentinel. It validates the target input, attempts a TCP connection using
socket primitives, and returns a typed scan result while handling common
network errors gracefully.
"""

from __future__ import annotations

import errno
import logging
import socket
import time
from datetime import datetime, timezone
from typing import Optional

from app.scanner.constants import DEFAULT_TIMEOUT
from app.scanner.models import ScanResult
from app.scanner.validator import (
    HostnameValidationError,
    IPv4ValidationError,
    IPv6ValidationError,
    PortValidationError,
    ValidationError,
    validate_hostname,
    validate_ipv4,
    validate_ipv6,
    validate_port_number,
)


class TCPScanner:
    """Perform single-port TCP scans with graceful error handling."""

    def __init__(self, timeout: float = DEFAULT_TIMEOUT, logger: Optional[logging.Logger] = None) -> None:
        self.timeout = timeout
        self.logger = logger or logging.getLogger("netsentinel.scanner.tcp")

    def connect(self, host: str, port: int) -> ScanResult:
        """Scan a single TCP port and return a structured scan result."""
        return self.scan_port(host, port)

    def scan_port(self, host: str, port: int) -> ScanResult:
        """Attempt a TCP connection to a single host and port.

        The method validates the host and port, creates a TCP socket, applies a
        configurable timeout, performs the connection attempt with
        ``socket.connect_ex()``, measures the elapsed time, and returns a
        :class:`ScanResult` regardless of the outcome.
        """
        timestamp = self._timestamp()
        service_name = "Unknown"

        try:
            validated_host = self._validate_host(host)
            validated_port = validate_port_number(port)
            service_name = self._resolve_service_name(validated_port)
        except (ValidationError, TypeError) as exc:
            self.logger.warning("Invalid scan input for %s:%s: %s", host, port, exc)
            return ScanResult(
                host=str(host),
                port=int(port) if isinstance(port, int) else 0,
                protocol="tcp",
                status="ERROR",
                response_time=None,
                service_name="Unknown",
                error_message=str(exc),
                timestamp=timestamp,
            )

        sock: Optional[socket.socket] = None
        start_time = time.perf_counter()

        try:
            self.logger.info("Scanning TCP %s:%s", validated_host, validated_port)
            family, _, _, _, sockaddr = self._resolve_address(validated_host, validated_port)
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result_code = sock.connect_ex(sockaddr)
            elapsed = round(time.perf_counter() - start_time, 6)

            if result_code == 0:
                status = "OPEN"
                error_message = None
            elif result_code in {
                errno.ECONNREFUSED,
                getattr(errno, "WSAECONNREFUSED", None),
            }:
                status = "CLOSED"
                error_message = None
            else:
                status = "FILTERED"
                error_message = None

            return ScanResult(
                host=validated_host,
                port=validated_port,
                protocol="tcp",
                status=status,
                response_time=elapsed,
                service_name=service_name,
                error_message=error_message,
                timestamp=timestamp,
            )
        except socket.timeout as exc:
            self.logger.warning("TCP scan timed out for %s:%s: %s", validated_host, validated_port, exc)
            return ScanResult(
                host=validated_host,
                port=validated_port,
                protocol="tcp",
                status="FILTERED",
                response_time=round(time.perf_counter() - start_time, 6),
                service_name=service_name,
                error_message=str(exc),
                timestamp=timestamp,
            )
        except ConnectionRefusedError as exc:
            self.logger.warning("Connection refused for %s:%s: %s", validated_host, validated_port, exc)
            return ScanResult(
                host=validated_host,
                port=validated_port,
                protocol="tcp",
                status="CLOSED",
                response_time=round(time.perf_counter() - start_time, 6),
                service_name=service_name,
                error_message=str(exc),
                timestamp=timestamp,
            )
        except socket.gaierror as exc:
            self.logger.error("DNS lookup failed for %s: %s", validated_host, exc)
            return ScanResult(
                host=validated_host,
                port=validated_port,
                protocol="tcp",
                status="ERROR",
                response_time=None,
                service_name=service_name,
                error_message=str(exc),
                timestamp=timestamp,
            )
        except OSError as exc:
            self.logger.error("TCP scan error for %s:%s: %s", validated_host, validated_port, exc)
            return ScanResult(
                host=validated_host,
                port=validated_port,
                protocol="tcp",
                status="ERROR",
                response_time=None,
                service_name=service_name,
                error_message=str(exc),
                timestamp=timestamp,
            )
        except Exception as exc:  # pragma: no cover - defensive guard
            self.logger.exception("Unexpected TCP scan failure for %s:%s", validated_host, validated_port)
            return ScanResult(
                host=validated_host,
                port=validated_port,
                protocol="tcp",
                status="ERROR",
                response_time=None,
                service_name=service_name,
                error_message=str(exc),
                timestamp=timestamp,
            )
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    self.logger.debug("Socket close failed for %s:%s", validated_host, validated_port)

    def scan_range(self, host: str, start_port: int, end_port: int) -> None:
        """Scan a TCP port range.

        This method is intentionally left unimplemented for future work.
        """
        raise NotImplementedError("TCP port range scanning is not implemented yet")

    def _validate_host(self, host: str) -> str:
        """Validate the scan target using the shared scanner validators."""
        if not isinstance(host, str) or not host.strip():
            raise ValidationError("Host cannot be empty")

        candidate = host.strip()

        try:
            return validate_ipv4(candidate)
        except IPv4ValidationError:
            pass

        try:
            return validate_ipv6(candidate)
        except IPv6ValidationError:
            pass

        try:
            return validate_hostname(candidate)
        except HostnameValidationError as exc:
            raise ValidationError(f"Invalid host: {exc}") from exc

    def _resolve_address(self, host: str, port: int) -> tuple[int, str, int, str, tuple[object, ...]]:
        """Resolve the host and port to a socket address tuple."""
        try:
            address_info = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
        except socket.gaierror as exc:
            raise socket.gaierror(f"Unable to resolve host {host}: {exc}") from exc

        family, _, _, _, sockaddr = address_info[0]
        return family, "", 0, "", sockaddr

    def _resolve_service_name(self, port: int) -> str:
        """Return the well-known service name for the given port if known."""
        try:
            return socket.getservbyport(port, "tcp")
        except OSError:
            return "Unknown"

    def _timestamp(self) -> str:
        """Create an ISO 8601 timestamp for scan results."""
        return datetime.now(timezone.utc).isoformat()
