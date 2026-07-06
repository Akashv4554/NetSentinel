"""Main application routes.

This blueprint hosts the public pages and dashboard entry points for the
application.
"""

from __future__ import annotations

from flask import Blueprint, render_template

from app.controllers import MainController

main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def home() -> str:
    """Render the landing page for the application."""
    controller = MainController()
    context = controller.build_home_context()
    return render_template("index.html", **context)
