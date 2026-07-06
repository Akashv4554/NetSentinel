"""Tests for the synchronous multi-port TCP scanner behavior."""

from __future__ import annotations

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
