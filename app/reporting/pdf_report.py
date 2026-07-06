"""PDF report generation helpers for NetSentinel."""

from __future__ import annotations

from datetime import datetime
from io import BytesIO
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.schemas import HostScanResult, SecurityReport


class PDFReportBuilder:
    """Build a scan summary PDF report for a host scan."""

    def build(self, scan_result: HostScanResult, security_report: SecurityReport) -> bytes:
        """Create a PDF report in memory and return the bytes."""
        buffer = BytesIO()
        document = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=0.75 * inch,
            leftMargin=0.75 * inch,
            topMargin=0.75 * inch,
            bottomMargin=0.75 * inch,
        )
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "TitleStyle",
            parent=styles["Title"],
            fontSize=16,
            textColor=colors.HexColor("#0b5fff"),
            spaceAfter=0.2 * inch,
        )
        body_style = styles["BodyText"]
        sections: list[Any] = []
        sections.append(Paragraph("NetSentinel Security Report", title_style))
        sections.append(Paragraph("Company: NetSentinel Security", body_style))
        sections.append(Spacer(1, 0.12 * inch))
        sections.append(Paragraph(f"Target Host: {scan_result.target_host}", body_style))
        sections.append(Paragraph(f"Date: {self._format_date(scan_result.created_at)}", body_style))
        sections.append(Paragraph(f"Duration: {scan_result.duration}s", body_style))
        sections.append(Paragraph(f"Open Ports: {scan_result.open_ports}", body_style))
        sections.append(Paragraph(f"Closed Ports: {scan_result.closed_ports}", body_style))
        sections.append(Paragraph(f"Services: {scan_result.most_common_service}", body_style))
        sections.append(Paragraph(f"Risk Score: {self._risk_score(security_report)}", body_style))
        sections.append(Spacer(1, 0.12 * inch))
        sections.append(Paragraph("Recommendations", styles["Heading2"]))
        recommendations = [
            f"- {recommendation.recommendation} (Severity: {recommendation.severity}, Risk: {recommendation.risk_score})"
            for recommendation in security_report.recommendations
        ] or ["- No specific recommendations."]
        for item in recommendations:
            sections.append(Paragraph(item, body_style))
        sections.append(Spacer(1, 0.2 * inch))
        data = [
            ["Metric", "Value"],
            ["Target Host", scan_result.target_host],
            ["Date", self._format_date(scan_result.created_at)],
            ["Duration", f"{scan_result.duration}s"],
            ["Open Ports", str(scan_result.open_ports)],
            ["Closed Ports", str(scan_result.closed_ports)],
        ]
        table = Table(data, repeatRows=1)
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0b5fff")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ]
            )
        )
        sections.append(table)
        document.build(sections)
        return buffer.getvalue()

    def _format_date(self, value: str | None) -> str:
        if not value:
            return datetime.utcnow().strftime("%Y-%m-%d")
        try:
            return datetime.fromisoformat(value).strftime("%Y-%m-%d")
        except ValueError:
            return value

    def _risk_score(self, security_report: SecurityReport) -> int:
        if not security_report.recommendations:
            return 0
        return max(recommendation.risk_score for recommendation in security_report.recommendations)
