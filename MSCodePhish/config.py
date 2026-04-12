"""Application configuration."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY") or "dev-secret-change-in-production"
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL") or f"sqlite:///{BASE_DIR / 'devicecode.db'}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    # Device code polling interval (seconds)
    DEVICE_CODE_POLL_INTERVAL = 5
    # Max time to wait for user to complete device auth (seconds, typically 900)
    DEVICE_CODE_EXPIRY = 900
