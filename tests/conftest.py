"""
Pytest configuration and environment fixtures for AI Compliance Layer.
Ensures clean test isolation and sets required environment defaults.
"""
import os
import pytest

@pytest.fixture(autouse=True)
def setup_test_environment(monkeypatch):
    """Ensures deterministic environment variables for tests without requiring local .env file."""
    monkeypatch.setenv("APP_BEARER_TOKEN", "mock-compliance-test-token")
    monkeypatch.setenv("USE_MOCK_LLM", "true")
