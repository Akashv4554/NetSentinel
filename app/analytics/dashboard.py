"""Dashboard analytics service for NetSentinel."""

from __future__ import annotations

from typing import Any

from app.analytics.charts import ChartBuilder
from app.analytics.statistics import StatisticsBuilder
from app.analytics.trends import TrendBuilder
from app.models import PortResult, ScanSession
from app.repositories import PortResultRepository, ScanSessionRepository
from app.schemas import InfrastructureOverview


class DashboardService:
    """Provide dashboard analytics using repository-backed read models."""

    def __init__(
        self,
        *,
        session_repo: ScanSessionRepository | None = None,
        result_repo: PortResultRepository | None = None,
    ) -> None:
        self._session_repo = session_repo or ScanSessionRepository()
        self._result_repo = result_repo or PortResultRepository()

    def get_dashboard_summary(self) -> dict[str, Any]:
        statistics = self._build_statistics()
        summary = statistics.build_summary()
        summary["top_services"] = statistics.top_services(limit=10)
        summary["top_hosts"] = statistics.top_hosts(limit=10)
        summary["top_open_ports"] = statistics.top_open_ports(limit=10)
        summary["recent_scans"] = statistics.recent_scans(limit=10)
        trends = self.get_scan_trends()
        summary["daily"] = trends["daily"]
        summary["weekly"] = trends["weekly"]
        summary["monthly"] = trends["monthly"]
        infrastructure_overview = self.get_infrastructure_overview()
        summary["infrastructure_overview"] = infrastructure_overview
        summary["high_risk_hosts"] = infrastructure_overview.critical_hosts
        return summary

    def get_infrastructure_overview(self) -> InfrastructureOverview:
        """Return the infrastructure overview widget payload."""
        from app.services import AnalyticsService

        sessions = self._load_sessions()
        port_results = self._load_port_results(sessions)
        return AnalyticsService(sessions=sessions, port_results=port_results).get_infrastructure_overview()

    def get_port_statistics(self) -> dict[str, Any]:
        statistics = self._build_statistics()
        return {
            "open_ports": statistics.open_ports(),
            "closed_ports": statistics.closed_ports(),
            "filtered_ports": statistics.filtered_ports(),
            "top_open_ports": statistics.top_open_ports(limit=10),
        }

    def get_service_statistics(self) -> dict[str, Any]:
        statistics = self._build_statistics()
        return {"top_services": statistics.top_services(limit=10)}

    def get_scan_trends(self) -> dict[str, Any]:
        sessions = self._load_sessions()
        trend_builder = TrendBuilder(sessions=sessions)
        return {
            "daily": trend_builder.daily_scan_count(),
            "weekly": trend_builder.weekly_scan_count(),
            "monthly": trend_builder.monthly_scan_count(),
        }

    def get_recent_scans(self, limit: int = 10) -> list[dict[str, Any]]:
        statistics = self._build_statistics()
        return statistics.recent_scans(limit=limit)

    def get_top_hosts(self, limit: int = 10) -> list[dict[str, Any]]:
        statistics = self._build_statistics()
        return statistics.top_hosts(limit=limit)

    def get_top_open_ports(self, limit: int = 10) -> list[dict[str, Any]]:
        statistics = self._build_statistics()
        return statistics.top_open_ports(limit=limit)

    def get_average_scan_duration(self) -> float:
        statistics = self._build_statistics()
        return statistics.average_scan_duration()

    def get_average_scan_speed(self) -> float:
        statistics = self._build_statistics()
        return statistics.average_scan_speed()

    def get_chart_data(self) -> dict[str, Any]:
        statistics = self._build_statistics()
        chart_builder = ChartBuilder(statistics)
        return {
            "service_distribution": chart_builder.pie_chart(
                label="Services",
                values=[{"label": item["service"], "value": item["count"]} for item in statistics.top_services(limit=10)],
            ),
            "port_distribution": chart_builder.doughnut_chart(
                label="Open Ports",
                values=[{"label": str(item["port"]), "value": item["count"]} for item in statistics.top_open_ports(limit=10)],
            ),
            "scan_trend": chart_builder.line_chart(
                label="Scans",
                values=[{"label": item["label"], "value": item["value"]} for item in TrendBuilder(sessions=self._load_sessions()).daily_scan_count()],
            ),
        }

    def _build_statistics(self) -> StatisticsBuilder:
        sessions = self._load_sessions()
        port_results = self._load_port_results(sessions)
        return StatisticsBuilder(sessions=sessions, port_results=port_results)

    def _load_sessions(self) -> list[ScanSession]:
        return self._session_repo.list_all()

    def _load_port_results(self, sessions: list[ScanSession]) -> list[PortResult]:
        results: list[PortResult] = []
        for session in sessions:
            results.extend(self._result_repo.list_for_session(session.id))
        return results
