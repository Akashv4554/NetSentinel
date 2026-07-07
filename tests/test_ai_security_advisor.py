from app.models import PortResult
from app.schemas import HostScanResult
from app.services.ai_security_advisor import AISecurityAdvisor
from app.services.security_advisor.rule_based import RuleBasedSecurityAssessmentProvider


def build_host_result(*, open_ports_list: list[int] | None = None) -> HostScanResult:
    return HostScanResult(
        scan_id=1,
        target_host="10.0.0.5",
        scan_type="tcp",
        protocol="tcp",
        total_ports=10,
        open_ports=len(open_ports_list or []),
        closed_ports=10 - len(open_ports_list or []),
        filtered_ports=0,
        duration=1.25,
        scan_speed=8.0,
        first_open_port=open_ports_list[0] if open_ports_list else None,
        last_open_port=open_ports_list[-1] if open_ports_list else None,
        most_common_service="http",
        status="completed",
        created_at="2024-01-01T00:00:00",
        open_ports_list=open_ports_list,
    )


def build_port_results(ports: list[tuple[int, str]]) -> list[PortResult]:
    return [
        PortResult(
            scan_session_id=1,
            port=port,
            protocol="tcp",
            service_name=service_name,
            status="OPEN",
        )
        for port, service_name in ports
    ]


def test_calculate_risk_score_applies_port_and_exposure_penalties() -> None:
    provider = RuleBasedSecurityAssessmentProvider()
    open_results = build_port_results([(22, "ssh"), (80, "http")])

    assert provider.calculate_risk_score(open_results) == 75


def test_calculate_risk_score_applies_unknown_service_and_database_penalties() -> None:
    provider = RuleBasedSecurityAssessmentProvider()
    open_results = build_port_results([(3306, "Unknown"), (8080, "Unknown")])

    assert provider.calculate_risk_score(open_results) == 40


def test_calculate_risk_score_is_clamped_between_zero_and_one_hundred() -> None:
    provider = RuleBasedSecurityAssessmentProvider()
    open_results = build_port_results(
        [
            (21, "ftp"),
            (23, "telnet"),
            (3306, "mysql"),
            (5432, "postgresql"),
            (1433, "mssql"),
            (1521, "oracle"),
            (25, "smtp"),
            (22, "ssh"),
            (80, "http"),
            (8080, "Unknown"),
            (8081, "Unknown"),
            (8082, "Unknown"),
        ]
    )

    assert provider.calculate_risk_score(open_results) == 0


def test_calculate_risk_level_maps_score_to_expected_categories() -> None:
    provider = RuleBasedSecurityAssessmentProvider()

    assert provider.calculate_risk_level(95) == "LOW"
    assert provider.calculate_risk_level(75) == "MEDIUM"
    assert provider.calculate_risk_level(45) == "HIGH"
    assert provider.calculate_risk_level(20) == "CRITICAL"


def test_analyze_generates_findings_recommendations_and_executive_summary() -> None:
    advisor = AISecurityAdvisor()
    host_result = build_host_result(open_ports_list=[22, 80])
    port_results = build_port_results([(22, "ssh"), (80, "http")])

    assessment = advisor.analyze(host_result, port_results)

    assert assessment.risk_score == 75
    assert assessment.risk_level == "MEDIUM"
    assert assessment.confidence == 95
    assert "Overall security posture is Medium Risk." in assessment.executive_summary
    assert any(finding.title == "SSH Exposed" for finding in assessment.findings)
    assert any(finding.title == "HTTP Service" for finding in assessment.findings)
    assert any(recommendation.text == "Restrict SSH access." for recommendation in assessment.recommendations)
    assert any(recommendation.text == "Use HTTPS instead of HTTP." for recommendation in assessment.recommendations)


def test_analyze_generates_recommendations_only_when_relevant() -> None:
    advisor = AISecurityAdvisor()
    host_result = build_host_result(open_ports_list=[])
    port_results: list[PortResult] = []

    assessment = advisor.analyze(host_result, port_results)

    assert assessment.risk_score == 100
    assert assessment.risk_level == "LOW"
    assert assessment.findings == []
    assert assessment.recommendations == []
    assert "Low Risk" in assessment.executive_summary


def test_generate_executive_summary_mentions_http_without_https() -> None:
    provider = RuleBasedSecurityAssessmentProvider()
    host_result = build_host_result(open_ports_list=[22, 80])
    findings = provider._build_findings(
        build_port_results([(22, "ssh"), (80, "http")]),
        {22, 80},
    )

    summary = provider.generate_executive_summary(
        host_result=host_result,
        open_count=2,
        findings=findings,
        risk_level="MEDIUM",
        open_ports={22, 80},
    )

    assert "HTTP is exposed without HTTPS" in summary


def test_calculate_confidence_reflects_unknown_services() -> None:
    provider = RuleBasedSecurityAssessmentProvider()
    known_results = build_port_results([(22, "ssh"), (80, "http"), (443, "https")])
    mixed_results = build_port_results([(22, "ssh"), (80, "http"), (8080, "Unknown")])

    assert provider.calculate_confidence(known_results) == 95
    assert provider.calculate_confidence(mixed_results) == 85
