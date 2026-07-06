"""Tests for the synchronous and threaded multi-port TCP scanner behavior."""

from __future__ import annotations

import socket
from contextlib import closing

import pytest

from app.scanner.tcp import TCPScanner


def test_scan_ports_returns_results_in_order() -> None:
    """scan_ports should return a scan result per requested port in order."""
    scanner = TCPScanner(timeout=0.2)
    results = scanner.scan_ports("127.0.0.1", [1, 2, 3])

    assert len(results) == 3
    assert [result.port for result in results] == [1, 2, 3]
    assert all(result.protocol == "tcp" for result in results)


def test_scan_range_returns_results_for_valid_range() -> None:
    """scan_range should scan the full requested range and preserve order."""
    scanner = TCPScanner(timeout=0.2)
    results = scanner.scan_range("127.0.0.1", 20, 22)

    assert len(results) == 3
    assert [result.port for result in results] == [20, 21, 22]


def test_scan_range_rejects_invalid_ranges() -> None:
    """scan_range should reject invalid ranges with a descriptive exception."""
    scanner = TCPScanner(timeout=0.2)

    with pytest.raises(ValueError):
        scanner.scan_range("127.0.0.1", 80, 20)


def test_scan_ports_handles_empty_input() -> None:
    """scan_ports should return an empty list for no ports."""
    scanner = TCPScanner(timeout=0.2)
    assert scanner.scan_ports("127.0.0.1", []) == []


def test_scan_range_handles_large_ranges() -> None:
    """scan_range should handle large ranges by returning many results."""
    scanner = TCPScanner(timeout=0.1)
    results = scanner.scan_range("127.0.0.1", 80, 90)

    assert len(results) == 11
    assert results[0].port == 80
    assert results[-1].port == 90


def test_scan_ports_threaded_returns_results_in_order() -> None:
    """Threaded scanning should preserve input order."""
    scanner = TCPScanner(timeout=0.05)
    results = scanner.scan_ports_threaded("127.0.0.1", [1, 2, 3], max_workers=3)

    assert len(results) == 3
    assert [result.port for result in results] == [1, 2, 3]
    assert all(result.protocol == "tcp" for result in results)


def test_scan_ports_threaded_handles_empty_input() -> None:
    """Threaded scanning should return an empty list when no ports are supplied."""
    scanner = TCPScanner(timeout=0.05)
    assert scanner.scan_ports_threaded("127.0.0.1", [], max_workers=2) == []


def test_scan_ports_threaded_rejects_invalid_worker_count() -> None:
    """Threaded scanning should validate the worker count."""
    scanner = TCPScanner(timeout=0.05)

    with pytest.raises(ValueError):
        scanner.scan_ports_threaded("127.0.0.1", [1], max_workers=0)


def test_scan_ports_threaded_handles_duplicates_and_failed_scans() -> None:
    """Threaded scanning should preserve duplicates and continue after failures."""
    scanner = TCPScanner(timeout=0.05)
    results = scanner.scan_ports_threaded("127.0.0.1", [1, 1, 65535], max_workers=3)

    assert len(results) == 3
    assert [result.port for result in results] == [1, 1, 65535]
    assert all(result.protocol == "tcp" for result in results)


def test_scan_ports_threaded_with_mixed_open_and_closed_ports() -> None:
    """Threaded scanning should support a mix of open and closed ports."""
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]

        scanner = TCPScanner(timeout=0.05)
        results = scanner.scan_ports_threaded("127.0.0.1", [port, 1, 2], max_workers=3)

    assert len(results) == 3
    assert {result.port for result in results} == {port, 1, 2}
    assert any(result.status == "OPEN" for result in results)
    assert any(result.status in {"CLOSED", "FILTERED", "ERROR"} for result in results)
