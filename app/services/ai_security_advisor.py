"""AI Security Advisor facade for scan result analysis."""

from __future__ import annotations

import logging
from typing import Optional

from app.models import PortResult
from app.schemas import HostScanResult, SecurityAssessment
from app.services.security_advisor.base import SecurityAssessmentProvider
from app.services.security_advisor.rule_based import RuleBasedSecurityAssessmentProvider

logger = logging.getLogger(__name__)


class AISecurityAdvisor:
    """Analyze completed scan results and produce an intelligent security assessment.

    This facade delegates to a pluggable inference provider so a future LLM-backed
    implementation can replace or augment the default rule-based engine.
    """

    def __init__(self, provider: Optional[SecurityAssessmentProvider] = None) -> None:
        self._provider = provider or RuleBasedSecurityAssessmentProvider()

    def analyze(
        self,
        host_result: HostScanResult,
        port_results: list[PortResult],
    ) -> SecurityAssessment:
        """Generate a security assessment for a completed scan."""
        logger.debug(
            "Generating AI security assessment for scan %s on %s",
            host_result.scan_id,
            host_result.target_host,
        )
        return self._provider.assess(host_result, port_results)
