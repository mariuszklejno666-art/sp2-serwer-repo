import pytest

from app import create_app
from app.config import ProductionConfig


def test_production_rejects_default_secret_key(monkeypatch):
    monkeypatch.setattr(
        ProductionConfig,
        "SECRET_KEY",
        "development-only-change-me",
    )
    monkeypatch.setattr(ProductionConfig, "SP2_API_TOKEN", "test-api-token")

    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        create_app("production")


def test_production_rejects_missing_api_token(monkeypatch):
    monkeypatch.setattr(ProductionConfig, "SECRET_KEY", "test-secret-key")
    monkeypatch.setattr(ProductionConfig, "SP2_API_TOKEN", "")

    with pytest.raises(RuntimeError, match="SP2_API_TOKEN"):
        create_app("production")


def test_production_accepts_required_secrets(monkeypatch):
    monkeypatch.setattr(ProductionConfig, "SECRET_KEY", "test-secret-key")
    monkeypatch.setattr(ProductionConfig, "SP2_API_TOKEN", "test-api-token")
    monkeypatch.setattr(
        ProductionConfig,
        "SQLALCHEMY_DATABASE_URI",
        "sqlite:///:memory:",
    )

    app = create_app("production")

    assert app.config["SECRET_KEY"] == "test-secret-key"
    assert app.config["SP2_API_TOKEN"] == "test-api-token"
