"""Simple CVE enrichment helper using the NVD public API.

This module provides a lightweight wrapper to query the NVD CVE search
endpoint and extract CVE id, summary and CVSS base score for matching
service/version keywords. The implementation is defensive: if the NVD
API is unreachable or an API key is not provided the methods return an
empty list so callers can continue with best-effort enrichment.
"""

from __future__ import annotations

import logging
import os
from typing import List

import requests

logger = logging.getLogger(__name__)


class CVEEnricher:
    """Query NVD for CVEs matching free-text keywords.

    Notes:
    - Honor `NVD_API_KEY` environment variable if present.
    - Keep the interface minimal to avoid coupling to NVD response
      structure for now.
    """

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, api_key: str | None = None, timeout: float = 8.0) -> None:
        self.api_key = api_key or os.getenv("NVD_API_KEY")
        self.timeout = timeout

    def match_keyword(self, keyword: str, max_results: int = 5) -> List[dict]:
        """Return a list of CVE matches for a free-text keyword.

        Each match is a dict: {'cve_id', 'summary', 'cvss'} where cvss is
        a float or None if unavailable.
        """
        if not keyword or not keyword.strip():
            return []

        params = {"keywordSearch": keyword, "resultsPerPage": max_results}
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        try:
            resp = requests.get(self.BASE_URL, params=params, headers=headers, timeout=self.timeout)
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:  # network errors, JSON parse errors, etc.
            logger.debug("NVD query failed for %s: %s", keyword, exc)
            return []

        vulns = data.get("vulnerabilities") or []
        results: list[dict] = []

        for v in vulns:
            cve = v.get("cve") or {}
            cve_id = cve.get("id")
            descriptions = cve.get("descriptions", [])
            summary = descriptions[0].get("value") if descriptions else ""

            # Extract a best-effort CVSS base score from available metric blocks
            cvss = None
            metrics = cve.get("metrics") or {}
            # prefer v3.1/3.0 then v2
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                block = metrics.get(key)
                if block and isinstance(block, list) and block:
                    try:
                        cvss = float(block[0]["cvssData"]["baseScore"])  # type: ignore[index]
                        break
                    except Exception:
                        continue

            results.append({"cve_id": cve_id, "summary": summary, "cvss": cvss})

        return results
