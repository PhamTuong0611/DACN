"""Pytest configuration and fixtures."""

import pytest
import asyncio


@pytest.fixture
def event_loop():
    """Provide event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def sample_certificate():
    """Provide sample certificate data."""
    return {
        "subject": [[("commonName", "example.com")]],
        "issuer": [[("commonName", "Let's Encrypt")]],
        "notAfter": "Jan  1 00:00:00 2099 GMT",
        "notBefore": "Jan  1 00:00:00 2020 GMT",
        "serialNumber": "1234567890",
        "subjectAltName": [("DNS", "example.com"), ("DNS", "*.example.com")],
    }


@pytest.fixture
def sample_headers():
    """Provide sample HTTP headers."""
    return {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Content-Security-Policy": "default-src 'self'",
    }
