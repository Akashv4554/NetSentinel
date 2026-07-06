from app.models import PortResult, ScanSession
from app.schemas import ComparisonReport, ServiceChange
from app.services import ScanComparisonService


def build_sessions() -> tuple[ScanSession, ScanSession]:
    previous = ScanSession(
        id=1,
        target_host="10.0.0.5",
        scan_type="tcp",
        protocol="tcp",
        status="completed",
        total_ports=100,
        open_ports=2,
        closed_ports=98,
        filtered_ports=0,
        duration=10.0,
        created_at=None,
    )
    current = ScanSession(
        id=2,
        target_host="10.0.0.5",
        scan_type="tcp",
        protocol="tcp",
        status="completed",
        total_ports=120,
        open_ports=3,
        closed_ports=117,
        filtered_ports=0,
        duration=14.0,
        created_at=None,
    )
    return previous, current


def test_scan_comparison_service_builds_expected_report() -> None:
    previous, current = build_sessions()
    previous_results = [
        PortResult(id=1, scan_session_id=1, port=22, protocol="tcp", service_name="ssh", status="OPEN", response_time=0.1),
        PortResult(id=2, scan_session_id=1, port=80, protocol="tcp", service_name="http", status="OPEN", response_time=0.2),
    ]
    current_results = [
        PortResult(id=3, scan_session_id=2, port=22, protocol="tcp", service_name="ssh", status="OPEN", response_time=0.1),
        PortResult(id=4, scan_session_id=2, port=80, protocol="tcp", service_name="https", status="OPEN", response_time=0.3),
        PortResult(id=5, scan_session_id=2, port=443, protocol="tcp", service_name="https", status="OPEN", response_time=0.4),
    ]

    service = ScanComparisonService()
    report = service.compare(previous, current, previous_results, current_results)

    assert isinstance(report, ComparisonReport)
    assert report.new_open_ports == [443]
    assert report.closed_ports == [
        {"port": 80, "previous_status": "OPEN", "current_status": "OPEN"},
    ]
    assert report.service_changes == [
        ServiceChange(port=80, previous_service="http", current_service="https")
    ]
    assert report.risk_score_difference == 20
    assert report.duration_difference == 4.0
    assert report.statistics_difference == {
        "total_ports": 20,
        "open_ports": 1,
        "closed_ports": 19,
        "filtered_ports": 0,
    }
