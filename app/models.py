"""SQLAlchemy models for persistent scan sessions and port results."""

from __future__ import annotations

from datetime import datetime, timezone

from app.extensions import db


class ScanSession(db.Model):  # type: ignore[name-defined]
    """Represents a single scan session executed by the scanner."""

    __tablename__ = "scan_sessions"

    id = db.Column(db.Integer, primary_key=True)
    target_host = db.Column(db.String(255), nullable=False)
    scan_type = db.Column(db.String(50), nullable=False)
    protocol = db.Column(db.String(20), nullable=False)
    start_time = db.Column(db.DateTime, nullable=True)
    end_time = db.Column(db.DateTime, nullable=True)
    duration = db.Column(db.Float, nullable=True)
    total_ports = db.Column(db.Integer, nullable=True, default=0)
    open_ports = db.Column(db.Integer, nullable=True, default=0)
    closed_ports = db.Column(db.Integer, nullable=True, default=0)
    filtered_ports = db.Column(db.Integer, nullable=True, default=0)
    status = db.Column(db.String(50), nullable=False, default="running")
    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    port_results = db.relationship(
        "PortResult",
        back_populates="scan_session",
        cascade="all, delete-orphan",
        lazy="select",
    )


class PortResult(db.Model):  # type: ignore[name-defined]
    """Represents the outcome of a single scanned port within a session."""

    __tablename__ = "port_results"

    id = db.Column(db.Integer, primary_key=True)
    scan_session_id = db.Column(
        db.Integer,
        db.ForeignKey("scan_sessions.id", ondelete="CASCADE"),
        nullable=False,
    )
    port = db.Column(db.Integer, nullable=False)
    protocol = db.Column(db.String(20), nullable=False)
    service_name = db.Column(db.String(100), nullable=True)
    status = db.Column(db.String(50), nullable=False, default="pending")
    response_time = db.Column(db.Float, nullable=True)
    error_message = db.Column(db.Text, nullable=True)

    scan_session = db.relationship("ScanSession", back_populates="port_results")


class Vulnerability(db.Model):  # type: ignore[name-defined]
    """Represents a vulnerability instance (CVE) discovered or recorded in the system."""

    __tablename__ = "vulnerabilities"

    id = db.Column(db.Integer, primary_key=True)
    cve_id = db.Column(db.String(50), nullable=False, index=True)
    summary = db.Column(db.Text, nullable=True)
    cvss = db.Column(db.Float, nullable=True)
    references = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    vulnerable_ports = db.relationship(
        "VulnerablePort",
        back_populates="vulnerability",
        cascade="all, delete-orphan",
        lazy="select",
    )


class VulnerablePort(db.Model):  # type: ignore[name-defined]
    """Join table linking a `PortResult` to discovered `Vulnerability` entries."""

    __tablename__ = "vulnerable_ports"

    id = db.Column(db.Integer, primary_key=True)
    port_result_id = db.Column(
        db.Integer, db.ForeignKey("port_results.id", ondelete="CASCADE"), nullable=False
    )
    vulnerability_id = db.Column(
        db.Integer, db.ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False
    )

    port_result = db.relationship("PortResult", backref="vulnerable_links")
    vulnerability = db.relationship("Vulnerability", back_populates="vulnerable_ports")
