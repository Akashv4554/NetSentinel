"""Controller layer for HTTP-facing application logic."""

from __future__ import annotations

from app.schemas import HomePageData
from app.services import DashboardService


class MainController:
    """Controller responsible for handling the main landing page."""

    def __init__(self, service: DashboardService | None = None) -> None:
        self._service = service or DashboardService()

    def build_home_context(self) -> dict[str, object]:
        """Prepare the data needed by the home page template."""
        data: HomePageData = self._service.get_home_dashboard_data()
        return {
            "title": data.title,
            "subtitle": data.subtitle,
            "scan_count": data.scan_count,
            "status": data.status,
        }
