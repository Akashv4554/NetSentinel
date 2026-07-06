"""High-level reporting service for NetSentinel."""

from __future__ import annotations

import json
from typing import Any

from app.reporting.csv_report import CSVReportBuilder
from app.reporting.pdf_report import PDFReportBuilder
from app.schemas import HostScanResult, SecurityReport


class ReportingService:
    """Generate downloadable PDF, CSV, and JSON reports from scan results."""

    def __init__(self) -> None:
        self._pdf_builder = PDFReportBuilder()
        self._csv_builder = CSVReportBuilder()

    def generate_pdf_report(self, scan_result: HostScanResult, security_report: SecurityReport) -> bytes:
        """Return a PDF report payload for download."""
        return self._pdf_builder.build(scan_result, security_report)

    def generate_csv_report(self, scan_result: HostScanResult) -> str:
        """Return CSV content for a scan result."""
        return self._csv_builder.build(scan_result)

    def generate_json_report(self, scan_result: HostScanResult, security_report: SecurityReport) -> dict[str, Any]:
        """Return a JSON-serializable report payload."""
        return {
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
