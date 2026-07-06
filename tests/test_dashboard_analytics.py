from datetime import datetime, timezone

from app.analytics import DashboardService
from app.models import PortResult, ScanSession
from app.repositories import PortResultRepository, ScanSessionRepository


class FakeSessionRepository(ScanSessionRepository):
    def __init__(self, sessions: list[ScanSession]) -> None:
        self._sessions = sessions

    def list_all(self) -> list[ScanSession]:
        return list(self._sessions)


class FakePortResultRepository(PortResultRepository):
    def __init__(self, results: list[PortResult]) -> None:
        self._results = results

    def list_for_session(self, session_id: int) -> list[PortResult]:
        return [result for result in self._results if result.scan_session_id == session_id]


def build_sessions_and_results() -> tuple[list[ScanSession], list[PortResult]]:
    sessions = [
        ScanSession(
            id=1,
            target_host="192.168.1.10",
            scan_type="tcp",
            protocol="tcp",
            status="completed",
            total_ports=100,
            open_ports=5,
            closed_ports=80,
            filtered_ports=15,
            duration=12.5,
            created_at=datetime(2024, 1, 2, 10, 0, tzinfo=timezone.utc),
        ),
        ScanSession(
            id=2,
            target_host="192.168.1.10",
            scan_type="tcp",
            protocol="tcp",
            status="completed",
            total_ports=200,
            open_ports=10,
            closed_ports=170,
            filtered_ports=20,
            duration=25.0,
            created_at=datetime(2024, 1, 3, 10, 0, tzinfo=timezone.utc),
        ),
    ]
    results = [
        PortResult(id=1, scan_session_id=1, port=80, protocol="tcp", service_name="http", status="OPEN", response_time=0.2),
        PortResult(id=2, scan_session_id=1, port=22, protocol="tcp", service_name="ssh", status="OPEN", response_time=0.1),
        PortResult(id=3, scan_session_id=2, port=443, protocol="tcp", service_name="https", status="CLOSED", response_time=0.3),
        PortResult(id=4, scan_session_id=2, port=80, protocol="tcp", service_name="http", status="OPEN", response_time=0.4),
    ]
    return sessions, results


def test_dashboard_service_returns_summary_statistics_and_trends() -> None:
    sessions, results = build_sessions_and_results()
    service = DashboardService(
        session_repo=FakeSessionRepository(sessions),
        result_repo=FakePortResultRepository(results),
    )

    summary = service.get_dashboard_summary()
    assert summary["total_scans"] == 2
    assert summary["total_hosts_scanned"] == 1
    assert summary["total_ports_scanned"] == 300
    assert summary["average_scan_duration"] == 18.75
    assert summary["average_scan_speed"] == 8.0
    assert summary["open_ports"] == 3
    assert summary["closed_ports"] == 1
    assert summary["filtered_ports"] == 0
    assert summary["top_services"] == [{"service": "http", "count": 2}, {"service": "https", "count": 1}, {"service": "ssh", "count": 1}]
    assert summary["top_hosts"] == [{"host": "192.168.1.10", "count": 2}]
    assert summary["top_open_ports"] == [{"port": 80, "count": 2}, {"port": 22, "count": 1}]
    assert len(summary["recent_scans"]) == 2

    port_stats = service.get_port_statistics()
    assert port_stats["top_open_ports"] == [{"port": 80, "count": 2}, {"port": 22, "count": 1}]

    service_stats = service.get_service_statistics()
    assert service_stats["top_services"][0]["service"] == "http"

    trends = service.get_scan_trends()
    assert trends["daily"][0]["label"] == "2024-01-02"
    assert trends["weekly"][0]["label"] == "2024-W01"
    assert trends["monthly"][0]["label"] == "2024-01"

    assert service.get_average_scan_duration() == 18.75
    assert service.get_average_scan_speed() == 8.0
    assert service.get_recent_scans(limit=1)[0]["host"] == "192.168.1.10"
    assert service.get_top_hosts(limit=5)[0]["host"] == "192.168.1.10"
    assert service.get_top_open_ports(limit=5)[0]["port"] == 80


def test_dashboard_service_returns_chart_payloads() -> None:
    sessions, results = build_sessions_and_results()
    service = DashboardService(
        session_repo=FakeSessionRepository(sessions),
        result_repo=FakePortResultRepository(results),
    )

    charts = service.get_chart_data()
    assert charts["service_distribution"]["type"] == "pie"
    assert charts["port_distribution"]["type"] == "doughnut"
    assert charts["scan_trend"]["type"] == "line"
