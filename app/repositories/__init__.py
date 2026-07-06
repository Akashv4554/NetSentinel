"""Repository layer for SQLAlchemy data access."""

from __future__ import annotations

from app.extensions import db
from app.models import ScanResult


class ScanRepository:
    """Repository responsible for scan-related database operations."""

    def count_scans(self) -> int:
        """Return the number of stored scan results."""
        return db.session.query(ScanResult).count()
