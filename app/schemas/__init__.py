"""Schema layer for data transfer objects and validation models."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class HomePageData:
    """Simple DTO for the home page view model."""

    title: str
    subtitle: str
    scan_count: int
    status: str
