"""SQLAlchemy models for NetSentinel.

This module will hold the domain models for scan results, hosts, services,
and related metadata as the project grows.
"""

from __future__ import annotations

from app.extensions import db


class ScanResult(db.Model):  # type: ignore[name-defined]
    """Placeholder model for future scan result persistence."""

    __tablename__ = "scan_results"

    id = db.Column(db.Integer, primary_key=True)
    host = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(50), nullable=False, default="pending")
