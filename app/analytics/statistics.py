"""Statistics aggregation helpers for dashboard analytics."""

from __future__ import annotations

from collections import Counter
from typing import Any

from app.models import PortResult, ScanSession


class StatisticsBuilder:
    """Build reusable statistics payloads from scan sessions and results."""

    def __init__(self, *, sessions: list[ScanSession], port_results: list[PortResult]) -> None:
        self._sessions = sessions
        self._port_results = port_results

    def build_summary(self) -> dict[str, Any]:
        """Return a compact summary for the dashboard."""
        return {
            "total_scans": self.total_scans(),
            "total_hosts_scanned": self.total_hosts_scanned(),
            "total_ports_scanned": self.total_ports_scanned(),
            "average_scan_duration": self.average_scan_duration(),
            "average_scan_speed": self.average_scan_speed(),
            "open_ports": self.open_ports(),
            "closed_ports": self.closed_ports(),
            "filtered_ports": self.filtered_ports(),
        }

    def total_scans(self) -> int:
        return len(self._sessions)

    def total_hosts_scanned(self) -> int:
        return len({session.target_host for session in self._sessions if session.target_host})

    def total_ports_scanned(self) -> int:
        return sum(session.total_ports or 0 for session in self._sessions)

    def average_scan_duration(self) -> float:
        durations = [session.duration for session in self._sessions if session.duration is not None]
        if not durations:
            return 0.0
        return round(sum(durations) / len(durations), 4)

    def average_scan_speed(self) -> float:
        speeds = [
            session.total_ports / session.duration
            for session in self._sessions
            if session.status == "completed"
            and session.total_ports is not None
            and session.duration is not None
            and session.duration > 0
        ]
        if not speeds:
            return 0.0
        return round(sum(speeds) / len(speeds), 4)

    def open_ports(self) -> int:
        return sum(1 for result in self._port_results if result.status == "OPEN")

    def closed_ports(self) -> int:
        return sum(1 for result in self._port_results if result.status == "CLOSED")

    def filtered_ports(self) -> int:
        return sum(1 for result in self._port_results if result.status == "FILTERED")

    def top_services(self, limit: int = 10) -> list[dict[str, Any]]:
        counter = Counter(result.service_name for result in self._port_results if result.service_name)
        return self._rank(counter, key_name="service", limit=limit)

    def top_hosts(self, limit: int = 10) -> list[dict[str, Any]]:
        counter = Counter(session.target_host for session in self._sessions if session.target_host)
        return self._rank(counter, key_name="host", limit=limit)

    def top_open_ports(self, limit: int = 10) -> list[dict[str, Any]]:
        counter = Counter(result.port for result in self._port_results if result.status == "OPEN")
        return self._rank(counter, key_name="port", limit=limit)

    def recent_scans(self, limit: int = 10) -> list[dict[str, Any]]:
        return [
            {
                "id": session.id,
                "host": session.target_host,
                "status": session.status,
                "created_at": session.created_at.isoformat() if session.created_at else None,
                "duration": session.duration,
            }
            for session in self._sessions[:limit]
        ]

    def _rank(self, counter: Counter[Any], *, key_name: str, limit: int) -> list[dict[str, Any]]:
        items = sorted(counter.items(), key=lambda item: (-item[1], str(item[0])))
        return [{key_name: value, "count": count} for value, count in items[:limit]]
