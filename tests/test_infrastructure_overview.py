from datetime import datetime, timezone

from app.models import PortResult, ScanSession
from app.services import AnalyticsService


def build_infrastructure_data() -> tuple[list[ScanSession], list[PortResult]]:
    """Build scan data covering healthy, warning, and critical scenarios."""
    sessions = [
        ScanSession(
            id=1,
            target_host="192.168.1.10",
            scan_type="tcp",
            protocol="tcp",
            status="completed",
            created_at=datetime(2024, 1, 3, 11, 58, tzinfo=timezone.utc),
        ),
        ScanSession(
            id=2,
            target_host="10.0.0.5",
            scan_type="tcp",
            protocol="tcp",
            status="completed",
            created_at=datetime(2024, 1, 3, 10, 0, tzinfo=timezone.utc),
        ),
        ScanSession(
            id=3,
            target_host="172.16.0.20",
            scan_type="tcp",
            protocol="tcp",
            status="completed",
            created_at=datetime(2024, 1, 3, 9, 0, tzinfo=timezone.utc),
        ),
        ScanSession(
            id=4,
            target_host="172.16.0.21",
            scan_type="tcp",
            protocol="tcp",
            status="completed",
            created_at=datetime(2024, 1, 3, 8, 0, tzinfo=timezone.utc),
        ),
        ScanSession(
            id=5,
            target_host="172.16.0.22",
            scan_type="tcp",
            protocol="tcp",
            status="completed",
            created_at=datetime(2024, 1, 3, 7, 0, tzinfo=timezone.utc),
        ),
    ]
    results = [
        PortResult(scan_session_id=1, port=22, protocol="tcp", service_name="ssh", status="OPEN"),
        PortResult(scan_session_id=2, port=21, protocol="tcp", service_name="ftp", status="OPEN"),
        PortResult(scan_session_id=3, port=23, protocol="tcp", service_name="telnet", status="OPEN"),
        PortResult(scan_session_id=4, port=3389, protocol="tcp", service_name="rdp", status="OPEN"),
        PortResult(scan_session_id=5, port=80, protocol="tcp", service_name="http", status="OPEN"),
        PortResult(scan_session_id=5, port=81, protocol="tcp", service_name="Unknown", status="OPEN"),
        PortResult(scan_session_id=5, port=82, protocol="tcp", service_name="http-alt", status="OPEN"),
        PortResult(scan_session_id=5, port=83, protocol="tcp", service_name="http-alt", status="OPEN"),
        PortResult(scan_session_id=5, port=84, protocol="tcp", service_name="http-alt", status="OPEN"),
        PortResult(scan_session_id=5, port=85, protocol="tcp", service_name="http-alt", status="OPEN"),
        PortResult(scan_session_id=5, port=86, protocol="tcp", service_name="http-alt", status="OPEN"),
    ]
    return sessions, results


def test_get_infrastructure_overview_returns_expected_metrics() -> None:
    sessions, results = build_infrastructure_data()
    service = AnalyticsService(sessions=sessions, port_results=results)

    overview = service.get_infrastructure_overview()

    assert overview.scanned_hosts == 5
    assert overview.open_ports == 11
    assert overview.critical_hosts == 4
    assert overview.detected_services == 6
    assert overview.last_scan_at == "2024-01-03T11:58:00+00:00"
    assert overview.system_health_status == "Critical"
    assert overview.system_health_badge_color == "danger"


def test_format_relative_time_returns_human_readable_values() -> None:
    reference_time = datetime(2024, 1, 3, 12, 0, tzinfo=timezone.utc)

    assert (
        AnalyticsService._format_relative_time(
            datetime(2024, 1, 3, 11, 58, tzinfo=timezone.utc),
            now=reference_time,
        )
        == "2 minutes ago"
    )
    assert (
        AnalyticsService._format_relative_time(
            datetime(2024, 1, 3, 11, 45, tzinfo=timezone.utc),
            now=reference_time,
        )
        == "15 minutes ago"
    )
    assert (
        AnalyticsService._format_relative_time(
            datetime(2024, 1, 3, 9, 0, tzinfo=timezone.utc),
            now=reference_time,
        )
        == "3 hours ago"
    )


def test_calculate_critical_hosts_uses_latest_scan_and_risk_rules() -> None:
    sessions = [
        ScanSession(
            id=1,
            target_host="192.168.1.10",
            scan_type="tcp",
            protocol="tcp",
            status="completed",
            created_at=datetime(2024, 1, 1, 10, 0, tzinfo=timezone.utc),
        ),
        ScanSession(
            id=2,
            target_host="192.168.1.10",
            scan_type="tcp",
            protocol="tcp",
            status="completed",
            created_at=datetime(2024, 1, 2, 10, 0, tzinfo=timezone.utc),
        ),
        ScanSession(
            id=3,
            target_host="10.0.0.5",
            scan_type="tcp",
            protocol="tcp",
            status="completed",
            created_at=datetime(2024, 1, 2, 9, 0, tzinfo=timezone.utc),
        ),
    ]
    results = [
        PortResult(scan_session_id=1, port=21, protocol="tcp", service_name="ftp", status="OPEN"),
        PortResult(scan_session_id=2, port=22, protocol="tcp", service_name="ssh", status="OPEN"),
        PortResult(scan_session_id=3, port=8080, protocol="tcp", service_name="http-proxy", status="OPEN"),
        PortResult(scan_session_id=3, port=8081, protocol="tcp", service_name="http-proxy", status="OPEN"),
        PortResult(scan_session_id=3, port=8082, protocol="tcp", service_name="http-proxy", status="OPEN"),
        PortResult(scan_session_id=3, port=8083, protocol="tcp", service_name="http-proxy", status="OPEN"),
        PortResult(scan_session_id=3, port=8084, protocol="tcp", service_name="http-proxy", status="OPEN"),
        PortResult(scan_session_id=3, port=8085, protocol="tcp", service_name="http-proxy", status="OPEN"),
        PortResult(scan_session_id=3, port=8086, protocol="tcp", service_name="http-proxy", status="OPEN"),
    ]
    service = AnalyticsService(sessions=sessions, port_results=results)

    assert service.calculate_critical_hosts() == 1


def test_calculate_system_health_returns_expected_statuses() -> None:
    assert AnalyticsService.calculate_system_health(0) == {
        "status": "Healthy",
        "badge_color": "success",
    }
    assert AnalyticsService.calculate_system_health(1) == {
        "status": "Warning",
        "badge_color": "warning",
    }
    assert AnalyticsService.calculate_system_health(3) == {
        "status": "Warning",
        "badge_color": "warning",
    }
    assert AnalyticsService.calculate_system_health(4) == {
        "status": "Critical",
        "badge_color": "danger",
    }


def test_infrastructure_overview_handles_empty_input() -> None:
    service = AnalyticsService(sessions=[], port_results=[])
    overview = service.get_infrastructure_overview()

    assert overview.scanned_hosts == 0
    assert overview.open_ports == 0
    assert overview.critical_hosts == 0
    assert overview.detected_services == 0
    assert overview.last_scan_time == "Not recorded"
    assert overview.last_scan_at is None
    assert overview.system_health_status == "Healthy"
    assert overview.system_health_badge_color == "success"
