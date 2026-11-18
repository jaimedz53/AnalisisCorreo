import pytest

from mxray.audit import audit_domain, audit_many, normalize_domain
from mxray.models import Status

from .conftest import FakeResolver


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("Example.COM", "example.com"),
        ("  jane.doe@Example.com ", "example.com"),
        ("https://www.example.com/contact", "www.example.com"),
        ("example.com.", "example.com"),
        ("bücher.de", "xn--bcher-kva.de"),
    ],
)
def test_normalize_domain(value, expected):
    assert normalize_domain(value) == expected


@pytest.mark.parametrize("value", ["", "localhost", "not a domain", "@", "user@"])
def test_normalize_rejects_invalid(value):
    with pytest.raises(ValueError):
        normalize_domain(value)


def test_secure_domain_scores_100(secure_resolver):
    report = audit_domain("someone@example.com", secure_resolver)
    assert report.domain == "example.com"
    assert report.provider == "Google Workspace / Gmail"
    assert report.score == 100
    assert report.risk == "low"
    assert [c.name for c in report.checks] == ["mx", "spf", "dmarc", "dkim", "mta-sts"]


def test_unconfigured_domain_is_high_risk(empty_resolver):
    report = audit_domain("example.org", empty_resolver)
    assert report.provider == "No mail server"
    assert report.risk == "high"
    # Only DKIM (INFO, unknown) gets partial credit.
    assert report.score == 8


def test_dns_failure_becomes_warning_not_crash():
    resolver = FakeResolver(failing={"example.com", "_dmarc.example.com"})
    report = audit_domain("example.com", resolver)
    assert report.get("mx").status is Status.WARN
    assert report.get("dmarc").status is Status.WARN
    assert "DNS lookup failed" in report.get("spf").message


def test_to_dict_is_json_friendly(secure_resolver):
    data = audit_domain("example.com", secure_resolver).to_dict()
    assert data["risk"] == "low"
    assert data["checks"][0]["status"] == "ok"
    assert data["mx"][0] == {"priority": 1, "host": "aspmx.l.google.com"}


def test_audit_many_deduplicates(secure_resolver):
    reports = audit_many(["example.com", "example.com", "other.com"], secure_resolver)
    assert list(reports) == ["example.com", "other.com"]
