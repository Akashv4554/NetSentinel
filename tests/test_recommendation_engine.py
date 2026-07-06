from app.schemas import HostScanResult, SecurityReport
from app.services import RecommendationEngine


def test_recommendation_engine_generates_rule_based_recommendations() -> None:
    scan_result = HostScanResult(
        scan_id=1,
        target_host="10.0.0.5",
        scan_type="tcp",
        protocol="tcp",
        total_ports=4,
        open_ports=4,
        closed_ports=0,
        filtered_ports=0,
        duration=1.25,
        scan_speed=3.2,
        first_open_port=21,
        last_open_port=3389,
        most_common_service="http",
        status="completed",
        created_at="2024-01-01T00:00:00",
        open_ports_list=[21, 22, 80, 3389],
    )

    engine = RecommendationEngine()
    report = engine.generate(scan_result)

    assert isinstance(report, SecurityReport)
    assert report.target_host == "10.0.0.5"
    assert [recommendation.port for recommendation in report.recommendations] == [21, 22, 80, 3389]
    assert report.recommendations[0].recommendation == "Consider SFTP or FTPS."
    assert report.recommendations[1].severity == "medium"
    assert report.recommendations[1].risk_score == 65
    assert report.recommendations[2].recommendation == "Use HTTPS for sensitive applications."
    assert report.recommendations[3].recommendation == "Restrict Remote Desktop access."


def test_recommendation_engine_returns_empty_report_for_no_open_ports() -> None:
    scan_result = HostScanResult(
        scan_id=2,
        target_host="192.168.1.200",
        scan_type="tcp",
        protocol="tcp",
        total_ports=10,
        open_ports=0,
        closed_ports=10,
        filtered_ports=0,
        duration=0.5,
        scan_speed=20.0,
        first_open_port=None,
        last_open_port=None,
        most_common_service="Unknown",
        status="completed",
        created_at="2024-01-01T00:00:00",
        open_ports_list=[],
    )

    engine = RecommendationEngine()
    report = engine.generate(scan_result)

    assert report.target_host == "192.168.1.200"
    assert report.recommendations == []
