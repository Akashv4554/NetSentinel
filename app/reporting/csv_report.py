"""CSV report generation helpers for NetSentinel."""

from __future__ import annotations

import csv
import io
from typing import Any

from app.schemas import HostScanResult


class CSVReportBuilder:
    """Build a CSV export for scan results."""

    def build(self, scan_result: HostScanResult) -> str:
        """Return the CSV content as a string."""
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Port", "Status", "Service", "Response Time", "Protocol"])
        rows = self._rows(scan_result)
        writer.writerows(rows)
        return output.getvalue()

    def _rows(self, scan_result: HostScanResult) -> list[list[Any]]:
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
