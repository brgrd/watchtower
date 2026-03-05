"""
Shared pytest fixtures for the Watchtower test suite.

WATCHTOWER_PLACEHOLDER_MODE is forced to "true" so that no test accidentally
makes a live network request or hits the Groq API.  Individual tests that need
to exercise the real fetch/security logic patch `placeholder_mode` explicitly.
"""

import os
import sys

import pytest

# Ensure project root is importable before any agent.* import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Force placeholder mode globally — tests must never touch external services
os.environ["WATCHTOWER_PLACEHOLDER_MODE"] = "true"


# ---------------------------------------------------------------------------
# Reusable data fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def empty_ignore() -> dict:
    """A fresh, empty ignore registry."""
    return {"ignore_url": {}, "ignore_domain": {}, "ignore_url_prefix": {}}


@pytest.fixture
def sample_item() -> dict:
    """A single feed item as produced by a polling function."""
    return {
        "title": "CVE-2026-9999 — Critical RCE actively exploited in the wild",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-9999",
        "summary": "A heap overflow in OpenSSL 3.x allows remote code execution via TLS.",
        "source": "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "source_id": "nvd",
        "source_type": "json_api",
        "source_category": "vulns",
        "source_country": "US",
        "country": "US",
        "published_at": "2026-03-01T00:00:00",
    }


@pytest.fixture
def sample_card() -> dict:
    """A cluster card as produced by the findings pipeline."""
    return {
        "id": "abc123def456",
        "title": "CVE-2026-9999 — Critical RCE actively exploited in the wild",
        "risk_score": 92,
        "priority": "P1",
        "domains": ["crypto_lib", "os_kernel"],
        "countries": ["US"],
        "summary": "[P1] Heap overflow. Why now: Active KEV listing. (confidence: 0.95)",
        "why_now": "Active KEV listing.",
        "confidence": 0.95,
        "recommended_actions_24h": ["Patch OpenSSL to 3.3.2+"],
        "recommended_actions_7d": ["Complete libssl inventory"],
        "sources": {
            "primary": [
                {
                    "title": "NVD Advisory",
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-9999",
                }
            ],
            "secondary": [],
        },
    }
