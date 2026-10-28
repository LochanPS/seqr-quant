"""Tests for origin discovery — pure parsing + IP classification (no network)."""
from unittest.mock import patch

from scanner.origin_discovery import _extract_subdomains, _is_cdn_or_unusable


def test_extract_subdomains_filters_to_domain():
    crt = [
        {"name_value": "api.example.com\norigin.example.com"},
        {"name_value": "*.example.com"},          # wildcard ignored
        {"name_value": "example.com"},
        {"name_value": "unrelated.other.com"},    # different domain ignored
    ]
    subs = _extract_subdomains(crt, "example.com")
    assert "api.example.com" in subs
    assert "origin.example.com" in subs
    assert "example.com" in subs
    assert "unrelated.other.com" not in subs
    assert all("*" not in s for s in subs)


def test_extract_subdomains_handles_empty():
    assert _extract_subdomains([], "example.com") == set()
    assert _extract_subdomains([{"name_value": ""}], "example.com") == set()


def test_private_ip_is_unusable():
    assert _is_cdn_or_unusable("10.0.0.5") is True
    assert _is_cdn_or_unusable("127.0.0.1") is True
    assert _is_cdn_or_unusable("169.254.1.1") is True


def test_invalid_ip_is_unusable():
    assert _is_cdn_or_unusable("not-an-ip") is True
    assert _is_cdn_or_unusable("") is True


def test_cloudflare_ip_classified_as_cdn():
    # 104.16.0.1 is in Cloudflare's 104.16.0.0/13 range.
    assert _is_cdn_or_unusable("104.16.0.1") is True


def test_direct_public_ip_is_candidate():
    # Public IP outside CDN CIDR ranges with non-CDN reverse-DNS → usable candidate.
    with patch("scanner.network._reverse_dns_cdn", return_value=""):
        assert _is_cdn_or_unusable("8.8.8.8") is False
