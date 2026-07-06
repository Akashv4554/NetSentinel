"""Chart.js-ready data builders for dashboard analytics."""

from __future__ import annotations

from typing import Any

from app.analytics.statistics import StatisticsBuilder


class ChartBuilder:
    """Build chart payloads directly usable by Chart.js."""

    def __init__(self, statistics: StatisticsBuilder) -> None:
        self._statistics = statistics

    def bar_chart(self, *, label: str, values: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "type": "bar",
            "data": {
                "labels": [item.get("label", "") for item in values],
                "datasets": [
                    {
                        "label": label,
                        "data": [item.get("value", 0) for item in values],
                    }
                ],
            },
        }

    def pie_chart(self, *, label: str, values: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "type": "pie",
            "data": {
                "labels": [item.get("label", "") for item in values],
                "datasets": [
                    {
                        "label": label,
                        "data": [item.get("value", 0) for item in values],
                    }
                ],
            },
        }

    def line_chart(self, *, label: str, values: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "type": "line",
            "data": {
                "labels": [item.get("label", "") for item in values],
                "datasets": [
                    {
                        "label": label,
                        "data": [item.get("value", 0) for item in values],
                    }
                ],
            },
        }

    def doughnut_chart(self, *, label: str, values: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "type": "doughnut",
            "data": {
                "labels": [item.get("label", "") for item in values],
                "datasets": [
                    {
                        "label": label,
                        "data": [item.get("value", 0) for item in values],
                    }
                ],
            },
        }
