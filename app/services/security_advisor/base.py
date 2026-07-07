"""Abstract base for security assessment inference providers."""

from __future__ import annotations

from abc import ABC, abstractmethod

from app.models import PortResult
from app.schemas import HostScanResult, SecurityAssessment


class SecurityAssessmentProvider(ABC):
    """Interface for generating security assessments from scan results.

    Implementations may be rule-based today and LLM-backed in the future
    without changing consumers of ``AISecurityAdvisor``.
    """

    @abstractmethod
    def assess(
        self,
        host_result: HostScanResult,
        port_results: list[PortResult],
    ) -> SecurityAssessment:
        """Analyze scan results and return a structured security assessment."""
