"""Network monitor service for local machine statistics."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

try:
    import psutil
except ModuleNotFoundError:  # pragma: no cover - runtime safeguard
    class _PsutilShim:
        """Fallback shim used when psutil is unavailable in runtime."""

        @staticmethod
        def net_io_counters(*, pernic: bool = False) -> Any:
            raise RuntimeError("psutil is not installed")

        @staticmethod
        def net_if_stats() -> dict[str, Any]:
            return {}

    psutil = _PsutilShim()  # type: ignore[assignment]

logger = logging.getLogger("netsentinel.network_monitor")


@dataclass(slots=True)
class NetworkMonitorSnapshot:
    """Structured payload for live network monitor metrics."""

    interface_name: str
    bytes_sent: int
    bytes_received: int
    packets_sent: int
    packets_received: int
    upload_speed: float
    download_speed: float
    upload_speed_human: str
    download_speed_human: str
    last_updated: str


class NetworkMonitorService:
    """Read host network statistics and estimate transfer speeds."""

    def __init__(self) -> None:
        self._previous_counters: Optional[Any] = None
        self._previous_timestamp: Optional[datetime] = None

    def get_snapshot(self) -> NetworkMonitorSnapshot:
        """Return the current network monitor snapshot."""
        now = datetime.now(timezone.utc)
        try:
            interface_name, counters = self._select_interface_and_counters()
        except Exception:  # pragma: no cover - defensive guard
            logger.exception("Unable to read network counters")
            return NetworkMonitorSnapshot(
                interface_name="Unknown",
                bytes_sent=0,
                bytes_received=0,
                packets_sent=0,
                packets_received=0,
                upload_speed=0.0,
                download_speed=0.0,
                upload_speed_human="Unavailable",
                download_speed_human="Unavailable",
                last_updated=now.isoformat(),
            )

        upload_speed = 0.0
        download_speed = 0.0
        if self._previous_counters is not None and self._previous_timestamp is not None:
            elapsed = max((now - self._previous_timestamp).total_seconds(), 1e-9)
            upload_speed = max((counters.bytes_sent - self._previous_counters.bytes_sent) / elapsed, 0.0)
            download_speed = max((counters.bytes_recv - self._previous_counters.bytes_recv) / elapsed, 0.0)

        self._previous_counters = counters
        self._previous_timestamp = now

        snapshot = NetworkMonitorSnapshot(
            interface_name=interface_name,
            bytes_sent=counters.bytes_sent,
            bytes_received=counters.bytes_recv,
            packets_sent=counters.packets_sent,
            packets_received=counters.packets_recv,
            upload_speed=upload_speed,
            download_speed=download_speed,
            upload_speed_human=self._format_speed(upload_speed),
            download_speed_human=self._format_speed(download_speed),
            last_updated=now.isoformat(),
        )
        logger.debug("Network monitor snapshot collected: %s", snapshot)
        return snapshot

    def _select_interface_and_counters(self) -> tuple[str, Any]:
        """Select an active interface and associated counters.

        The service prefers interfaces that are UP, non-virtual, and with the
        highest observed network activity. If no suitable interface is found,
        it falls back to system-wide counters.
        """
        stats = psutil.net_if_stats()
        pernic_counters = psutil.net_io_counters(pernic=True) or {}
        best_interface: Optional[str] = None
        best_counters: Optional[Any] = None
        best_activity = -1

        for name, details in stats.items():
            counters = pernic_counters.get(name)
            if counters is None or not details.isup:
                continue
            if self._is_excluded_interface(name):
                continue

            activity = (
                int(counters.bytes_sent)
                + int(counters.bytes_recv)
                + int(counters.packets_sent)
                + int(counters.packets_recv)
            )
            if activity > best_activity:
                best_interface = name
                best_counters = counters
                best_activity = activity

        if best_interface is not None and best_counters is not None:
            return best_interface, best_counters

        # Fall back to system-wide counters when no suitable interface exists.
        fallback_counters = psutil.net_io_counters()
        return "Unknown", fallback_counters

    @staticmethod
    def _is_excluded_interface(interface_name: str) -> bool:
        lowered = interface_name.lower()
        excluded_tokens = (
            "loopback",
            "vbox",
            "virtualbox",
            "vmware",
            "hyper-v",
            "veth",
            "vethernet",
            "wsl",
            "bluetooth",
            "isatap",
            "teredo",
            "docker",
        )
        return lowered.startswith("lo") or any(token in lowered for token in excluded_tokens)

    @staticmethod
    def _format_speed(bytes_per_second: float) -> str:
        """Format transfer speed using KB/s or MB/s."""
        kb_per_second = bytes_per_second / 1024
        if kb_per_second < 1024:
            return f"{kb_per_second:.2f} KB/s"
        mb_per_second = kb_per_second / 1024
        return f"{mb_per_second:.2f} MB/s"
