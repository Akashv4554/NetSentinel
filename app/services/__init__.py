"""Service layer for application business logic."""

from __future__ import annotations

from app.repositories import ScanRepository
from app.schemas import HomePageData


class DashboardService:
    """Service responsible for preparing dashboard and home page data."""

    def __init__(self, repository: ScanRepository | None = None) -> None:
        self._repository = repository or ScanRepository()

    def get_home_dashboard_data(self) -> HomePageData:
        """Return simple view-model data for the landing page."""
        scan_count = self._repository.count_scans()
        return HomePageData(
            title="NetSentinel",
            subtitle="Intelligent Network Port Scanner & Service Analysis Dashboard",
            scan_count=scan_count,
            status="ready",
        )
