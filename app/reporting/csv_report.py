"""CSV report generation helpers for NetSentinel."""

from __future__ import annotations

import csv
import io
from typing import Any

from app.models import PortResult
from app.schemas import HostScanResult, SecurityAssessment


class CSVReportBuilder:
    """Build a CSV export for scan results."""

    def build(
        self,
        scan_result: HostScanResult,
        *,
        port_results: list[PortResult] | None = None,
        security_assessment: SecurityAssessment | None = None,
    ) -> str:
        """Return the CSV content as a string."""
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Port", "Status", "Service", "Response Time", "Protocol"])
        writer.writerows(self._rows(scan_result, port_results))
        if security_assessment is not None:
            writer.writerow([])
            writer.writerow(["AI Security Assessment"])
            writer.writerow(["Risk Score", security_assessment.risk_score])
            writer.writerow(["Risk Level", security_assessment.risk_level])
            writer.writerow(["Confidence", f"{security_assessment.confidence}%"])
            writer.writerow(["Executive Summary", security_assessment.executive_summary])
            writer.writerow([])
            writer.writerow(["Finding Title", "Severity", "Description"])
            for finding in security_assessment.findings:
                writer.writerow([finding.title, finding.severity, finding.description])
            writer.writerow([])
            writer.writerow(["Recommendation", "Priority"])
            for recommendation in security_assessment.recommendations:
                writer.writerow([recommendation.text, recommendation.priority])
        return output.getvalue()

    def _rows(
        self,
        scan_result: HostScanResult,
        port_results: list[PortResult] | None,
    ) -> list[list[Any]]:
        if port_results:
            return [
                [
                    result.port,
                    result.status,
                    result.service_name or "Unknown",
                    result.response_time if result.response_time is not None else "0.1",
                    result.protocol,
                ]
                for result in port_results
            ]
        if not scan_result.open_ports_list:
            return []
        return [
            [
                port,
                "OPEN",
                scan_result.most_common_service,
                "0.1",
                scan_result.protocol,
            ]
            for port in scan_result.open_ports_list
        ]
