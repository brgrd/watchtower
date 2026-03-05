"""
Tests for URL safety enforcement in agent.runner.

fetch_url has several security layers that must all be independently
verifiable.  Each test patches `placeholder_mode` to False so the real
security checks are exercised (the conftest sets placeholder=true globally
to prevent accidental live requests; these tests intentionally override that).
"""

import pytest
from unittest.mock import MagicMock, patch

from agent.runner import fetch_url, is_private_host

pytestmark = pytest.mark.unit


# ── is_private_host (exhaustive edge cases) ───────────────────────────────────


class TestIsPrivateHostEdgeCases:
    def test_172_prefix_blocked(self):
        # 172.x.x.x is in PRIVATE_PREFIXES
        assert is_private_host("https://172.99.0.1/api") is True

    def test_subdomain_of_local_blocked(self):
        assert is_private_host("https://dev.myapp.local/secret") is True

    def test_lan_subdomain_blocked(self):
        assert is_private_host("https://printer.office.lan/") is True

    def test_ipv6_loopback_blocked(self):
        # IPv6 URIs require bracket notation: https://[::1]/path
        assert is_private_host("https://[::1]/ipv6") is True

    def test_localhost_hostname_not_explicitly_blocked(self):
        # "localhost" is not in PRIVATE_PREFIXES and doesn't end in .local/.lan
        # but 127.0.0.1 IS blocked; document this behaviour
        assert is_private_host("https://127.0.0.1/api") is True

    def test_public_ip_allowed(self):
        assert is_private_host("https://8.8.8.8/dns") is False


# ── fetch_url security gates ──────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _disable_placeholder(monkeypatch):
    """Ensure security checks run (not the placeholder short-circuit)."""
    monkeypatch.setattr("agent.runner.placeholder_mode", lambda: False)


class TestFetchUrlSecurity:
    def test_http_scheme_rejected(self):
        with pytest.raises(ValueError, match="Non-HTTPS blocked"):
            fetch_url("http://example.com/page")

    def test_private_host_rejected(self):
        with pytest.raises(ValueError, match="Private network host blocked"):
            fetch_url("https://192.168.1.1/admin")

    def test_aws_metadata_endpoint_rejected(self):
        with pytest.raises(ValueError, match="Private network host blocked"):
            fetch_url("https://169.254.169.254/latest/meta-data/")

    def test_executable_content_type_rejected(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"content-type": "application/octet-stream"}
        mock_resp.text = "binary"
        with patch("agent.runner.requests.Session") as MockSess:
            MockSess.return_value.get.return_value = mock_resp
            with pytest.raises(ValueError, match="content-type blocked"):
                fetch_url("https://example.com/malware.exe")

    def test_zip_content_type_rejected(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"content-type": "application/zip"}
        mock_resp.text = "PK..."
        with patch("agent.runner.requests.Session") as MockSess:
            MockSess.return_value.get.return_value = mock_resp
            with pytest.raises(ValueError, match="content-type blocked"):
                fetch_url("https://example.com/archive.zip")

    def test_document_too_large_rejected(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"content-type": "text/html"}
        mock_resp.text = "a" * 2_100_000
        with patch("agent.runner.requests.Session") as MockSess:
            MockSess.return_value.get.return_value = mock_resp
            with pytest.raises(ValueError, match="Document too large"):
                fetch_url("https://example.com/huge-page")

    def test_insufficient_text_rejected(self):
        from unittest.mock import patch as mpatch

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"content-type": "text/html"}
        mock_resp.text = "<html><body>short</body></html>"
        with patch("agent.runner.requests.Session") as MockSess:
            MockSess.return_value.get.return_value = mock_resp
            with pytest.raises(ValueError, match="Insufficient text"):
                fetch_url("https://example.com/empty-page")

    def test_valid_response_returns_text(self):
        long_text = "Security advisory content. " * 20  # >200 chars of visible text
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"content-type": "text/html; charset=utf-8"}
        mock_resp.text = f"<html><body><p>{long_text}</p></body></html>"
        with patch("agent.runner.requests.Session") as MockSess:
            MockSess.return_value.get.return_value = mock_resp
            result = fetch_url("https://example.com/valid-advisory")
        assert isinstance(result, str)
        assert len(result) > 0


class TestFetchUrlPlaceholderMode:
    def test_placeholder_returns_without_network(self, monkeypatch):
        # Override the autouse fixture — we WANT placeholder mode here
        monkeypatch.setattr("agent.runner.placeholder_mode", lambda: True)
        result = fetch_url("https://example.com/anything")
        assert result == "placeholder content"
