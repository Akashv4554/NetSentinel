"""High-level reporting service for NetSentinel."""

from __future__ import annotations

import json
from typing import Any

from app.reporting.csv_report import CSVReportBuilder
from app.reporting.pdf_report import PDFReportBuilder
from app.models import PortResult
from app.schemas import HostScanResult, SecurityAssessment, SecurityReport


class ReportingService:
    """Generate downloadable PDF, CSV, and JSON reports from scan results."""

    def __init__(self) -> None:
        self._pdf_builder = PDFReportBuilder()
        self._csv_builder = CSVReportBuilder()

    def generate_pdf_report(
        self,
        scan_result: HostScanResult,
        security_report: SecurityReport,
        security_assessment: SecurityAssessment | None = None,
    ) -> bytes:
        """Return a PDF report payload for download."""
        return self._pdf_builder.build(scan_result, security_report, security_assessment)

    def generate_csv_report(
        self,
        scan_result: HostScanResult,
        *,
        port_results: list[PortResult] | None = None,
        security_assessment: SecurityAssessment | None = None,
    ) -> str:
        """Return CSV content for a scan result."""
        return self._csv_builder.build(scan_result, port_results=port_results, security_assessment=security_assessment)

    def generate_json_report(
        self,
        scan_result: HostScanResult,
        security_report: SecurityReport,
        security_assessment: SecurityAssessment | None = None,
    ) -> dict[str, Any]:
        """Return a JSON-serializable report payload."""
        payload: dict[str, Any] = {
            "target_host": scan_result.target_host,
            "scan_type": scan_result.scan_type,
            "protocol": scan_result.protocol,
            "duration": scan_result.duration,
            "open_ports": scan_result.open_ports,
            "closed_ports": scan_result.closed_ports,
            "filtered_ports": scan_result.filtered_ports,
            "services": [scan_result.most_common_service],
            "recommendations": [
                {
                    "port": recommendation.port,
                    "recommendation": recommendation.recommendation,
                    "severity": recommendation.severity,
                    "risk_score": recommendation.risk_score,
                }
                for recommendation in security_report.recommendations
            ],
        }
        if security_assessment is not None:
            payload["ai_security_assessment"] = self._serialize_assessment(security_assessment)
        return payload

    @staticmethod
    def _serialize_assessment(security_assessment: SecurityAssessment) -> dict[str, Any]:
        """Serialize a security assessment for report exports."""
        return {
            "risk_score": security_assessment.risk_score,
            "risk_level": security_assessment.risk_level,
            "executive_summary": security_assessment.executive_summary,
            "confidence": security_assessment.confidence,
            "findings": [
                {
                    "title": finding.title,
                    "severity": finding.severity,
                    "description": finding.description,
                }
                for finding in security_assessment.findings
            ],
            "recommendations": [
                {
                    "text": recommendation.text,
                    "priority": recommendation.priority,
                }
                for recommendation in security_assessment.recommendations
            ],
        }
