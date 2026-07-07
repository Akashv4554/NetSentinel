"""Deterministic rule-based security assessment inference engine."""

from __future__ import annotations

import logging
from typing import Any

from app.models import PortResult
from app.schemas import AdvisorRecommendation, HostScanResult, SecurityAssessment, SecurityFinding
from app.services.security_advisor.base import SecurityAssessmentProvider

logger = logging.getLogger(__name__)

DATABASE_PORTS = {3306, 5432, 1433, 1521}
PORT_PENALTIES: dict[int, int] = {
    22: 10,
    80: 15,
    21: 25,
    23: 35,
    25: 10,
    3306: 40,
    5432: 40,
    1433: 40,
    1521: 40,
}
PORT_FINDINGS: dict[int, tuple[str, str, str]] = {
    22: ("SSH Exposed", "Medium", "SSH is reachable from the network."),
    80: ("HTTP Service", "Low", "HTTP service detected."),
    21: ("FTP Exposed", "High", "Legacy FTP service is accessible from the network."),
    23: ("Telnet Exposed", "Critical", "Telnet transmits credentials in cleartext."),
    25: ("SMTP Exposed", "Medium", "SMTP mail service is reachable from the network."),
    3306: ("MySQL Database Exposed", "Critical", "MySQL database port is accessible from the network."),
    5432: ("PostgreSQL Database Exposed", "Critical", "PostgreSQL database port is accessible from the network."),
    1433: ("MSSQL Database Exposed", "Critical", "Microsoft SQL Server port is accessible from the network."),
    1521: ("Oracle Database Exposed", "Critical", "Oracle database listener is accessible from the network."),
}
PORT_RECOMMENDATIONS: dict[int, tuple[str, str]] = {
    22: ("Restrict SSH access.", "High"),
    80: ("Use HTTPS instead of HTTP.", "High"),
    21: ("Remove legacy protocols.", "High"),
    23: ("Remove legacy protocols.", "Critical"),
    25: ("Restrict SMTP relay and require authentication.", "Medium"),
    3306: ("Restrict database access.", "Critical"),
    5432: ("Restrict database access.", "Critical"),
    1433: ("Restrict database access.", "Critical"),
    1521: ("Restrict database access.", "Critical"),
}


class RuleBasedSecurityAssessmentProvider(SecurityAssessmentProvider):
    """Generate assessments using deterministic port and service heuristics."""

    def assess(
        self,
        host_result: HostScanResult,
        port_results: list[PortResult],
    ) -> SecurityAssessment:
        """Analyze scan results and return a rule-based security assessment."""
        open_results = [result for result in port_results if result.status == "OPEN"]
        open_ports = {result.port for result in open_results}
        findings = self._build_findings(open_results, open_ports)
        recommendations = self._build_recommendations(open_results, open_ports)
        risk_score = self.calculate_risk_score(open_results)
        risk_level = self.calculate_risk_level(risk_score)
        confidence = self.calculate_confidence(open_results)
        executive_summary = self.generate_executive_summary(
            host_result=host_result,
            open_count=len(open_results),
            findings=findings,
            risk_level=risk_level,
            open_ports=open_ports,
        )
        assessment = SecurityAssessment(
            risk_score=risk_score,
            risk_level=risk_level,
            executive_summary=executive_summary,
            findings=findings,
            recommendations=recommendations,
            confidence=confidence,
        )
        logger.info(
            "Rule-based security assessment generated for %s: score=%s level=%s confidence=%s%%",
            host_result.target_host,
            risk_score,
            risk_level,
            confidence,
        )
        return assessment

    def calculate_risk_score(self, open_results: list[PortResult]) -> int:
        """Calculate risk score starting at 100 and subtracting based on findings."""
        score = 100
        open_ports = {result.port for result in open_results}

        for port in open_ports:
            score -= PORT_PENALTIES.get(port, 0)

        for result in open_results:
            if not self._is_known_service(result.service_name):
                score -= 10

        open_count = len(open_results)
        if open_count > 10:
            score -= 40
        elif open_count > 5:
            score -= 20

        return max(0, min(100, score))

    @staticmethod
    def calculate_risk_level(risk_score: int) -> str:
        """Map a numeric risk score to a categorical risk level."""
        if risk_score >= 81:
            return "LOW"
        if risk_score >= 61:
            return "MEDIUM"
        if risk_score >= 31:
            return "HIGH"
        return "CRITICAL"

    def calculate_confidence(self, open_results: list[PortResult]) -> int:
        """Estimate assessment confidence from service detection quality."""
        if not open_results:
            return 95

        known_count = sum(1 for result in open_results if self._is_known_service(result.service_name))
        total_count = len(open_results)
        unknown_count = total_count - known_count
        known_ratio = known_count / total_count
        confidence = int(75 + known_ratio * 20 - unknown_count * 3)
        return max(60, min(100, confidence))

    def generate_executive_summary(
        self,
        *,
        host_result: HostScanResult,
        open_count: int,
        findings: list[SecurityFinding],
        risk_level: str,
        open_ports: set[int],
    ) -> str:
        """Generate a short executive summary paragraph for the assessment."""
        if open_count == 0:
            return (
                f"The scan of {host_result.target_host} did not identify any publicly accessible services. "
                "Overall security posture is Low Risk."
            )

        service_phrase = (
            f"{open_count} publicly accessible service{'s' if open_count != 1 else ''}"
        )
        opening = f"The scan identified {service_phrase}."

        if findings:
            concern_titles = ", ".join(finding.title.lower() for finding in findings[:3])
            middle = (
                "Most services appear to be standard network services; however, "
                f"the assessment flagged concerns including {concern_titles}."
            )
            if 80 in open_ports and 443 not in open_ports:
                middle = (
                    "Most services appear to be standard network services; however, "
                    "HTTP is exposed without HTTPS and multiple administrative ports may be accessible."
                )
        else:
            middle = "Most services appear to be standard network services with no major concerns detected."

        closing = f"Overall security posture is {risk_level.title()} Risk."
        return f"{opening} {middle} {closing}"

    def _build_findings(
        self,
        open_results: list[PortResult],
        open_ports: set[int],
    ) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        seen_titles: set[str] = set()

        for port in sorted(open_ports):
            template = PORT_FINDINGS.get(port)
            if template is None:
                continue
            title, severity, description = template
            if title in seen_titles:
                continue
            findings.append(SecurityFinding(title=title, severity=severity, description=description))
            seen_titles.add(title)

        for result in open_results:
            if self._is_known_service(result.service_name):
                continue
            title = f"Unknown Service on Port {result.port}"
            if title in seen_titles:
                continue
            findings.append(
                SecurityFinding(
                    title=title,
                    severity="Medium",
                    description="An unidentified service is listening on an open port.",
                )
            )
            seen_titles.add(title)

        open_count = len(open_results)
        if open_count > 10:
            findings.append(
                SecurityFinding(
                    title="Excessive Port Exposure",
                    severity="High",
                    description="More than ten ports are open, increasing the attack surface.",
                )
            )
        elif open_count > 5:
            findings.append(
                SecurityFinding(
                    title="High Port Exposure",
                    severity="Medium",
                    description="More than five ports are open, which may indicate unnecessary exposure.",
                )
            )

        return findings

    def _build_recommendations(
        self,
        open_results: list[PortResult],
        open_ports: set[int],
    ) -> list[AdvisorRecommendation]:
        recommendations: list[AdvisorRecommendation] = []
        seen_text: set[str] = set()

        def add_recommendation(text: str, priority: str) -> None:
            if text in seen_text:
                return
            recommendations.append(AdvisorRecommendation(text=text, priority=priority))
            seen_text.add(text)

        for port in sorted(open_ports):
            template = PORT_RECOMMENDATIONS.get(port)
            if template is not None:
                add_recommendation(*template)

        if 80 in open_ports and 443 not in open_ports:
            add_recommendation("Use HTTPS instead of HTTP.", "High")

        if any(port in DATABASE_PORTS for port in open_ports):
            add_recommendation("Restrict database access.", "Critical")

        if len(open_results) > 5:
            add_recommendation("Close unnecessary ports.", "High")

        if len(open_results) > 3:
            add_recommendation("Disable unused services.", "Medium")

        if open_results:
            add_recommendation("Enable firewall rules.", "Medium")
            add_recommendation("Review exposed services.", "Low")

        return recommendations

    @staticmethod
    def _is_known_service(service_name: str | None) -> bool:
        return bool(service_name and service_name.strip() and service_name.lower() != "unknown")
