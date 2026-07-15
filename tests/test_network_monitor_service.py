from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

from app.services.network_monitor import NetworkMonitorService


def test_network_monitor_service_returns_snapshot(monkeypatch) -> None:
    monkeypatch.setattr(
        "app.services.network_monitor.psutil.net_io_counters",
        lambda pernic=False: {
            "Wi-Fi": SimpleNamespace(
                bytes_sent=1024,
                bytes_recv=2048,
                packets_sent=10,
                packets_recv=20,
            ),
        } if pernic else SimpleNamespace(
            bytes_sent=0,
            bytes_recv=0,
            packets_sent=0,
            packets_recv=0,
        ),
    )
    monkeypatch.setattr(
        "app.services.network_monitor.psutil.net_if_stats",
        lambda: {
            "Wi-Fi": SimpleNamespace(isup=True),
            "Loopback Pseudo-Interface": SimpleNamespace(isup=True),
        },
    )

    snapshot = NetworkMonitorService().get_snapshot()

    assert snapshot.interface_name == "Wi-Fi"
    assert snapshot.bytes_sent == 1024
    assert snapshot.bytes_received == 2048
    assert snapshot.packets_sent == 10
    assert snapshot.packets_received == 20
    assert snapshot.upload_speed == 0.0
    assert snapshot.download_speed == 0.0
    assert snapshot.upload_speed_human == "0.00 KB/s"
    assert snapshot.download_speed_human == "0.00 KB/s"
    assert snapshot.last_updated


def test_network_monitor_service_calculates_speeds(monkeypatch) -> None:
    service = NetworkMonitorService()
    samples = iter(
        [
            SimpleNamespace(bytes_sent=1000, bytes_recv=1000, packets_sent=10, packets_recv=10),
            SimpleNamespace(bytes_sent=5000, bytes_recv=9000, packets_sent=20, packets_recv=30),
        ]
    )
    timestamps = iter(
        [
            datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
            datetime(2026, 1, 1, 0, 0, 2, tzinfo=timezone.utc),
        ]
    )

    monkeypatch.setattr(
        "app.services.network_monitor.psutil.net_io_counters",
        lambda pernic=False: {"Ethernet": next(samples)} if pernic else SimpleNamespace(
            bytes_sent=0,
            bytes_recv=0,
            packets_sent=0,
            packets_recv=0,
        ),
    )
    monkeypatch.setattr("app.services.network_monitor.psutil.net_if_stats", lambda: {"Ethernet": SimpleNamespace(isup=True)})
    monkeypatch.setattr("app.services.network_monitor.datetime", SimpleNamespace(now=lambda _tz: next(timestamps)))

    first = service.get_snapshot()
    second = service.get_snapshot()

    assert first.upload_speed == 0.0
    assert first.download_speed == 0.0
    assert second.upload_speed == 2000.0
    assert second.download_speed == 4000.0
    assert second.upload_speed_human.endswith("KB/s")
    assert second.download_speed_human.endswith("KB/s")


def test_network_monitor_service_returns_unknown_interface(monkeypatch) -> None:
    monkeypatch.setattr(
        "app.services.network_monitor.psutil.net_io_counters",
        lambda pernic=False: {"Loopback": SimpleNamespace(
            bytes_sent=1000,
            bytes_recv=2000,
            packets_sent=10,
            packets_recv=20,
        )} if pernic else SimpleNamespace(
            bytes_sent=555,
            bytes_recv=777,
            packets_sent=8,
            packets_recv=9,
        ),
    )
    monkeypatch.setattr(
        "app.services.network_monitor.psutil.net_if_stats",
        lambda: {"Loopback": SimpleNamespace(isup=True)},
    )

    snapshot = NetworkMonitorService().get_snapshot()
    assert snapshot.interface_name == "Unknown"
    assert snapshot.bytes_sent == 555
    assert snapshot.bytes_received == 777


def test_network_monitor_service_selects_highest_activity_interface(monkeypatch) -> None:
    monkeypatch.setattr(
        "app.services.network_monitor.psutil.net_io_counters",
        lambda pernic=False: {
            "Ethernet": SimpleNamespace(bytes_sent=100, bytes_recv=100, packets_sent=1, packets_recv=1),
            "Wi-Fi": SimpleNamespace(bytes_sent=2000, bytes_recv=4000, packets_sent=20, packets_recv=30),
            "vEthernet (Default Switch)": SimpleNamespace(bytes_sent=9000, bytes_recv=9000, packets_sent=99, packets_recv=99),
        } if pernic else SimpleNamespace(bytes_sent=0, bytes_recv=0, packets_sent=0, packets_recv=0),
    )
    monkeypatch.setattr(
        "app.services.network_monitor.psutil.net_if_stats",
        lambda: {
            "Ethernet": SimpleNamespace(isup=True),
            "Wi-Fi": SimpleNamespace(isup=True),
            "vEthernet (Default Switch)": SimpleNamespace(isup=True),
        },
    )

    snapshot = NetworkMonitorService().get_snapshot()
    assert snapshot.interface_name == "Wi-Fi"
    assert snapshot.bytes_received == 4000
