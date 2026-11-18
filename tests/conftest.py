from __future__ import annotations

import pytest

from mxray.resolver import DNSLookupError


class FakeResolver:
    """In-memory DNS. Names listed in ``failing`` raise DNSLookupError."""

    def __init__(self, mx=None, txt=None, failing=()):
        self._mx = mx or {}
        self._txt = txt or {}
        self._failing = set(failing)

    def _check(self, name):
        if name in self._failing:
            raise DNSLookupError(f"simulated failure for {name}")

    def mx(self, domain):
        self._check(domain)
        return sorted(self._mx.get(domain, []))

    def txt(self, name):
        self._check(name)
        return list(self._txt.get(name, []))


@pytest.fixture
def secure_resolver():
    """A well configured domain on Google Workspace."""
    return FakeResolver(
        mx={"example.com": [(1, "aspmx.l.google.com"), (5, "alt1.aspmx.l.google.com")]},
        txt={
            "example.com": ["v=spf1 include:_spf.google.com -all", "google-site-verification=x"],
            "_spf.google.com": ["v=spf1 include:_netblocks.google.com ~all"],
            "_netblocks.google.com": ["v=spf1 ip4:35.190.247.0/24 ~all"],
            "_dmarc.example.com": ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"],
            "google._domainkey.example.com": ["v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOC"],
            "_mta-sts.example.com": ["v=STSv1; id=20240101"],
        },
    )


@pytest.fixture
def empty_resolver():
    return FakeResolver()
