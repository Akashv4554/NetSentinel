"""Security advisor inference providers."""

from app.services.security_advisor.base import SecurityAssessmentProvider
from app.services.security_advisor.rule_based import RuleBasedSecurityAssessmentProvider

__all__ = [
    "SecurityAssessmentProvider",
    "RuleBasedSecurityAssessmentProvider",
]
