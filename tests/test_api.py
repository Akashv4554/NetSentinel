"""Tests for the NetSentinel REST API."""

from __future__ import annotations

from app import create_app
from app.extensions import db


def test_api_health_and_scan_workflow() -> None:
    """The API should expose health and scan endpoints."""
    app = create_app("testing")
    with app.test_client() as client:
        health = client.get("/api/health")
        assert health.status_code == 200
        assert health.get_json()["status"] == "ok"

        scan_response = client.post(
            "/api/scan",
            json={"host": "127.0.0.1", "start_port": 1, "end_port": 3, "threads": 2},
        )
        assert scan_response.status_code == 200
        assert scan_response.get_json()["status"] == "completed"

        scans = client.get("/api/scans")
        assert scans.status_code == 200
        assert scans.get_json()["items"]

        scan_detail = client.get(f"/api/scans/{scan_response.get_json()['scan_id']}")
        assert scan_detail.status_code == 200

        dashboard = client.get("/api/dashboard")
        assert dashboard.status_code == 200
        assert dashboard.get_json()["total_scans"] >= 1

        delete_response = client.delete(f"/api/scans/{scan_response.get_json()['scan_id']}")
        assert delete_response.status_code == 200
