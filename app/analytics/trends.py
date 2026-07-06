"""Trend aggregation helpers for dashboard analytics."""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any

from app.models import ScanSession


class TrendBuilder:
    """Build daily, weekly, and monthly scan trend groups."""

    def __init__(self, *, sessions: list[ScanSession]) -> None:
        self._sessions = sessions

    def daily_scan_count(self) -> list[dict[str, Any]]:
        counter = Counter(session.created_at.date().isoformat() for session in self._sessions if session.created_at is not None)
        return [{"label": day, "value": count} for day, count in sorted(counter.items())]

    def weekly_scan_count(self) -> list[dict[str, Any]]:
        counter = Counter(self._week_label(session) for session in self._sessions if session.created_at is not None)
        return [{"label": week, "value": count} for week, count in sorted(counter.items())]

    def monthly_scan_count(self) -> list[dict[str, Any]]:
        counter = Counter(session.created_at.strftime("%Y-%m") for session in self._sessions if session.created_at is not None)
        return [{"label": month, "value": count} for month, count in sorted(counter.items())]

    def _week_label(self, session: ScanSession) -> str:
        if session.created_at is None:
            return ""
        iso_year, iso_week, _ = session.created_at.isocalendar()
        return f"{iso_year}-W{iso_week:02d}"
