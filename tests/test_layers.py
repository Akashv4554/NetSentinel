"""Tests for the layered application architecture."""

from app.controllers import MainController
from app.repositories import ScanRepository
from app.services import DashboardService


def test_layered_components_are_importable() -> None:
    """The layered modules should be importable without circular issues."""
    controller = MainController()
    service = DashboardService()
    repository = ScanRepository()

    assert controller is not None
    assert service is not None
    assert repository is not None
