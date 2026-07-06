"""Smoke tests for the NetSentinel Flask application skeleton."""

from flask.testing import FlaskClient

from app import create_app


def test_home_page_renders() -> None:
    """The application factory should create a working Flask app."""
    app = create_app("testing")
    app.config.update(TESTING=True)

    with app.test_client() as client:  # type: FlaskClient
        response = client.get("/")

    assert response.status_code == 200
    assert b"NetSentinel" in response.data
