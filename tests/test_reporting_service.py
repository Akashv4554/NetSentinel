from datetime import datetime, timezone

from app.reporting.report_service import ReportingService
from app.schemas import (
    AdvisorRecommendation,
    HostScanResult,
    Recommendation,
    SecurityAssessment,
    SecurityFinding,
    SecurityReport,
)


def test_reporting_service_generates_pdf_csv_and_json_exports() -> None:
    scan_result = HostScanResult(
        scan_id=1,
        target_host="10.0.0.5",
        scan_type="tcp",
        protocol="tcp",
        total_ports=4,
        open_ports=2,
        closed_ports=2,
        filtered_ports=0,
        duration=1.25,
        scan_speed=3.2,
        first_open_port=22,
        last_open_port=80,
        most_common_service="http",
        status="completed",
        created_at="2024-01-01T00:00:00",
        open_ports_list=[22, 80],
    )
    security_report = SecurityReport(
        target_host="10.0.0.5",
        recommendations=[
            Recommendation(port=22, recommendation="Use key authentication.", severity="medium", risk_score=65),
            Recommendation(port=80, recommendation="Use HTTPS for sensitive applications.", severity="medium", risk_score=70),
        ],
    )

    service = ReportingService()

    pdf_bytes = service.generate_pdf_report(scan_result, security_report)
    assert isinstance(pdf_bytes, bytes)
    assert pdf_bytes.startswith(b"%PDF")

    csv_content = service.generate_csv_report(scan_result)
    assert "Port,Status,Service,Response Time,Protocol" in csv_content
    assert "22,OPEN,http,0.1,tcp" in csv_content

    json_payload = service.generate_json_report(scan_result, security_report)
    assert json_payload["target_host"] == "10.0.0.5"
    assert json_payload["open_ports"] == 2
    assert json_payload["recommendations"][0]["port"] == 22


def test_reporting_service_includes_ai_security_assessment_when_provided() -> None:
    scan_result = HostScanResult(
        scan_id=1,
        target_host="10.0.0.5",
        scan_type="tcp",
        protocol="tcp",
        total_ports=2,
        open_ports=2,
        closed_ports=0,
        filtered_ports=0,
        duration=1.25,
        scan_speed=3.2,
        first_open_port=22,
        last_open_port=80,
        most_common_service="http",
        status="completed",
        created_at="2024-01-01T00:00:00",
        open_ports_list=[22, 80],
    )
    security_report = SecurityReport(target_host="10.0.0.5", recommendations=[])
    security_assessment = SecurityAssessment(
        risk_score=75,
        risk_level="MEDIUM",
        executive_summary="Overall security posture is Medium Risk.",
        findings=[
            SecurityFinding(
                title="SSH Exposed",
                severity="Medium",
                description="SSH is reachable from the network.",
            )
        ],
        recommendations=[AdvisorRecommendation(text="Restrict SSH access.", priority="High")],
        confidence=92,
    )
    service = ReportingService()

    pdf_without = service.generate_pdf_report(scan_result, security_report)
    pdf_bytes = service.generate_pdf_report(scan_result, security_report, security_assessment)
    assert isinstance(pdf_bytes, bytes)
    assert pdf_bytes.startswith(b"%PDF")
    assert len(pdf_bytes) > len(pdf_without)

    csv_content = service.generate_csv_report(scan_result, security_assessment=security_assessment)
    assert "AI Security Assessment" in csv_content
    assert "Restrict SSH access." in csv_content

    json_payload = service.generate_json_report(scan_result, security_report, security_assessment)
    assert json_payload["ai_security_assessment"]["risk_score"] == 75
    assert json_payload["ai_security_assessment"]["findings"][0]["title"] == "SSH Exposed"


def test_reporting_service_handles_empty_input() -> None:
    service = ReportingService()
    scan_result = HostScanResult(
        scan_id=2,
        target_host="192.168.1.200",
        scan_type="tcp",
        protocol="tcp",
        total_ports=0,
        open_ports=0,
        closed_ports=0,
        filtered_ports=0,
        duration=0.0,
        scan_speed=0.0,
        first_open_port=None,
        last_open_port=None,
        most_common_service="Unknown",
        status="completed",
        created_at="2024-01-01T00:00:00",
        open_ports_list=[],
    )

    pdf_bytes = service.generate_pdf_report(scan_result, SecurityReport(target_host="192.168.1.200", recommendations=[]))
    assert isinstance(pdf_bytes, bytes)
    assert pdf_bytes.startswith(b"%PDF")

    csv_content = service.generate_csv_report(scan_result)
    assert csv_content.startswith("Port,Status,Service,Response Time,Protocol")

    json_payload = service.generate_json_report(scan_result, SecurityReport(target_host="192.168.1.200", recommendations=[]))
    assert json_payload["recommendations"] == []
