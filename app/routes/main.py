"""Main application routes.

This blueprint hosts the public pages and dashboard entry points for the
application.
"""

from __future__ import annotations

from flask import Blueprint, redirect, url_for

main_bp = Blueprint("main", __name__)


@main_bp.route("/landing")
def home() -> str:
    """Redirect legacy landing requests to the dashboard UI."""
    return redirect(url_for("ui.dashboard"))
