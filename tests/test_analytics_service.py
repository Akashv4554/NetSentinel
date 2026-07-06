from datetime import datetime, timedelta, timezone

from app.models import PortResult, ScanSession
from app.services import AnalyticsService


def build_sample_data() -> tuple[list[ScanSession], list[PortResult]]:
    sessions = [
        ScanSession(
            target_host="192.168.1.10",
            scan_type="tcp",
            protocol="tcp",
            status="completed",
            duration=10.0,
            total_ports=100,
            open_ports=5,
            closed_ports=80,
            filtered_ports=15,
            created_at=datetime(2024, 1, 2, 10, 0, tzinfo=timezone.utc),
        ),
        ScanSession(
            target_host="192.168.1.10",
            scan_type="tcp",
            protocol="tcp",
            status="completed",
            duration=20.0,
            total_ports=200,
            open_ports=10,
            closed_ports=170,
            filtered_ports=20,
            created_at=datetime(2024, 1, 2, 12, 0, tzinfo=timezone.utc),
        ),
        ScanSession(
            target_host="10.0.0.5",
            scan_type="tcp",
            protocol="tcp",
            status="failed",
            duration=30.0,
            total_ports=150,
            open_ports=0,
            closed_ports=140,
            filtered_ports=10,
            created_at=datetime(2024, 1, 3, 9, 0, tzinfo=timezone.utc),
        ),
    ]

    results = [
        PortResult(port=80, protocol="tcp", service_name="http", status="OPEN", response_time=0.25),
        PortResult(port=22, protocol="tcp", service_name="ssh", status="OPEN", response_time=0.15),
        PortResult(port=443, protocol="tcp", service_name="https", status="CLOSED", response_time=0.3),
        PortResult(port=80, protocol="tcp", service_name="http", status="OPEN", response_time=0.2),
        PortResult(port=53, protocol="tcp", service_name="dns", status="FILTERED", response_time=0.4),
    ]
    return sessions, results


def test_analytics_service_returns_expected_business_metrics() -> None:
    sessions, results = build_sample_data()
    service = AnalyticsService(sessions=sessions, port_results=results)

    assert service.get_total_scans() == 3
    assert service.calculate_average_scan_duration() == 20.0
    assert service.get_top_scanned_hosts(limit=5) == [
        {"host": "192.168.1.10", "count": 2},
        {"host": "10.0.0.5", "count": 1},
    ]
    assert service.get_most_common_open_ports(limit=5) == [
        {"port": 80, "count": 2},
        {"port": 22, "count": 1},
    ]
    assert service.get_most_common_services(limit=5) == [
        {"service": "http", "count": 2},
        {"service": "ssh", "count": 1},
        {"service": "https", "count": 1},
        {"service": "dns", "count": 1},
    ]
    assert service.get_daily_scan_count() == [
        {"date": "2024-01-02", "count": 2},
        {"date": "2024-01-03", "count": 1},
    ]
    assert service.get_weekly_scan_trend() == [
        {"week": "2024-W01", "count": 3},
    ]
    assert service.get_port_distribution() == {
        "OPEN": 3,
        "CLOSED": 1,
        "FILTERED": 1,
    }
    assert service.get_success_rate() == 0.6667
    assert service.get_average_scan_speed() == 10.0


def test_analytics_service_handles_empty_input() -> None:
    service = AnalyticsService(sessions=[], port_results=[])

    assert service.get_total_scans() == 0
    assert service.calculate_average_scan_duration() == 0.0
    assert service.get_top_scanned_hosts(limit=5) == []
    assert service.get_most_common_open_ports(limit=5) == []
    assert service.get_most_common_services(limit=5) == []
    assert service.get_daily_scan_count() == []
    assert service.get_weekly_scan_trend() == []
    assert service.get_port_distribution() == {}
    assert service.get_success_rate() == 0.0
    assert service.get_average_scan_speed() == 0.0
