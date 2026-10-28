"""Production configuration guardrails — refuse to boot insecurely."""
import pytest

from app.config import Settings


def _prod(**over):
    base = dict(
        ENVIRONMENT="production",
        SECRET_KEY="x" * 40,
        USE_FAKE_REDIS=False,
        DATABASE_URL="postgresql+asyncpg://u:p@host/db",
        FRONTEND_URL="https://app.seqrlabs.com",
    )
    base.update(over)
    return Settings(**base)


def test_production_rejects_default_secret():
    with pytest.raises(RuntimeError):
        _prod(SECRET_KEY="dev-secret-change-in-production").validate_production()


def test_production_rejects_short_secret():
    with pytest.raises(RuntimeError):
        _prod(SECRET_KEY="tooshort").validate_production()


def test_production_rejects_fake_redis():
    with pytest.raises(RuntimeError):
        _prod(USE_FAKE_REDIS=True).validate_production()


def test_production_rejects_sqlite():
    with pytest.raises(RuntimeError):
        _prod(DATABASE_URL="sqlite+aiosqlite:///./seqr.db").validate_production()


def test_production_rejects_localhost_frontend():
    with pytest.raises(RuntimeError):
        _prod(FRONTEND_URL="http://localhost:3000").validate_production()


def test_production_accepts_valid_config():
    _prod().validate_production()  # must not raise


def test_development_skips_validation():
    # Dev defaults must never raise.
    Settings(ENVIRONMENT="development").validate_production()
