"""Tests for the scanner foundation architecture."""

import pytest

from app.scanner.constants import DEFAULT_THREADS, DEFAULT_TIMEOUT, MAX_PORT, MIN_PORT
from app.scanner.engine import ScannerEngine
from app.scanner.models import Host, Port, ScanRequest, ScanResult
from app.scanner.tcp import TCPScanner
from app.scanner.validator import (
    PortRangeValidationError,
    PortValidationError,
    validate_hostname,
    validate_ipv4,
    validate_ipv6,
    validate_port_number,
    validate_port_range,
)


def test_validator_accepts_valid_inputs() -> None:
    """Validation helpers should accept common network values."""
    assert validate_ipv4("192.168.1.1") == "192.168.1.1"
    assert validate_ipv6("2001:db8::1") == "2001:db8::1"
    assert validate_hostname("example.com") == "example.com"
    assert validate_port_number(80) == 80
    assert validate_port_range(20, 80) == (20, 80)


def test_validator_rejects_invalid_ports() -> None:
    """Validation helpers should reject invalid port values clearly."""
    with pytest.raises(PortValidationError):
        validate_port_number(70000)

    with pytest.raises(PortRangeValidationError):
        validate_port_range(80, 20)


def test_scanner_engine_initializes_with_configuration() -> None:
    """The scanner engine should expose basic configuration fields."""
    engine = ScannerEngine(timeout=3.5, thread_count=25)

    assert engine.timeout == 3.5
    assert engine.thread_count == 25
    assert engine.logger.name == "netsentinel.scanner"


def test_tcp_scanner_methods_are_stubs() -> None:
    """TCP scanner methods should be intentionally unimplemented."""
    scanner = TCPScanner()

    with pytest.raises(NotImplementedError):
        scanner.connect("127.0.0.1", 80)

    with pytest.raises(NotImplementedError):
        scanner.scan_port("127.0.0.1", 80)

    with pytest.raises(NotImplementedError):
        scanner.scan_range("127.0.0.1", 20, 25)


def test_models_are_typed_dataclasses() -> None:
    """The scanner models should instantiate as typed data containers."""
    host = Host(hostname="localhost")
    port = Port(number=22, protocol="tcp")
    request = ScanRequest(target=host, ports=[port], timeout=DEFAULT_TIMEOUT)
    result = ScanResult(request=request, status="pending")

    assert host.hostname == "localhost"
    assert port.number == 22
    assert request.timeout == DEFAULT_TIMEOUT
    assert result.status == "pending"
    assert MIN_PORT <= 1 <= MAX_PORT
    assert DEFAULT_THREADS >= 1
