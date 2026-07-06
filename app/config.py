"""Configuration settings for the Flask application.

This module centralizes environment-specific settings for development,
testing, and production deployments.
"""

from __future__ import annotations

from pathlib import Path


class Config:
    """Base configuration shared across all environments."""

    SECRET_KEY: str = "dev-secret-key"
    SQLALCHEMY_DATABASE_URI: str = (
        f"sqlite:///{Path(__file__).resolve().parent.parent / 'instance' / 'netsentinel.db'}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS: bool = False
    DEBUG: bool = False
    TESTING: bool = False


class TestingConfig(Config):
    """Configuration used by the automated test suite."""

    TESTING: bool = True
    SQLALCHEMY_DATABASE_URI: str = "sqlite:///:memory:"
