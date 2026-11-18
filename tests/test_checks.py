import pytest

from mxray.checks import (
    check_dkim,
    check_dmarc,
    check_mta_sts,
    check_mx,
    check_spf,
    count_spf_lookups,
    parse_tags,
)
from mxray.models import MXRecord, Status

from .conftest import FakeResolver


def spf(record: str, **extra) -> FakeResolver:
    return FakeResolver(txt={"d.com": [record], **extra})


# --- MX ---------------------------------------------------------------------


def test_mx_ok():
    assert check_mx([MXRecord(10, "mx.d.com")]).status is Status.OK


def test_mx_missing():
    assert check_mx([]).status is Status.FAIL


def test_null_mx():
    assert check_mx([MXRecord(0, "")]).status is Status.INFO


# --- SPF --------------------------------------------------------------------


@pytest.mark.parametrize(
    ("record", "status"),
    [
        ("v=spf1 ip4:1.2.3.4 -all", Status.OK),
        ("v=spf1 ip4:1.2.3.4 ~all", Status.OK),
        ("v=spf1 ip4:1.2.3.4 ?all", Status.WARN),
        ("v=spf1 ip4:1.2.3.4", Status.WARN),
        ("v=spf1 +all", Status.FAIL),
        ("v=spf1 all", Status.FAIL),
        ("v=spf1 redirect=_spf.other.com", Status.OK),
    ],
)
def test_spf_all_mechanism(record, status):
    assert check_spf("d.com", spf(record)).status is status


def test_spf_missing():
    resolver = FakeResolver(txt={"d.com": ["some-verification=abc"]})
    assert check_spf("d.com", resolver).status is Status.FAIL


def test_spf_multiple_records_is_permerror():
    resolver = FakeResolver(txt={"d.com": ["v=spf1 -all", "v=spf1 ~all"]})
    check = check_spf("d.com", resolver)
    assert check.status is Status.FAIL
    assert "only one is allowed" in check.message


def test_spf_does_not_match_lookalike_prefix():
    # "v=spf10" is not an SPF record.
    resolver = FakeResolver(txt={"d.com": ["v=spf10 -all"]})
    assert check_spf("d.com", resolver).status is Status.FAIL


def test_spf_lookup_count_is_recursive():
    resolver = FakeResolver(
        txt={
            "a.com": ["v=spf1 include:b.com mx a -all"],
            "b.com": ["v=spf1 include:c.com ~all"],
            "c.com": ["v=spf1 a mx ~all"],
        }
    )
    # a.com: include + mx + a = 3; b.com: include = 1; c.com: a + mx = 2
    assert count_spf_lookups("v=spf1 include:b.com mx a -all", resolver) == 6


def test_spf_lookup_loop_does_not_hang():
    resolver = FakeResolver(txt={"loop.com": ["v=spf1 include:loop.com -all"]})
    assert count_spf_lookups("v=spf1 include:loop.com -all", resolver) == 2


def test_spf_too_many_lookups():
    includes = " ".join(f"include:i{n}.com" for n in range(11))
    check = check_spf("d.com", spf(f"v=spf1 {includes} -all"))
    assert check.status is Status.FAIL
    assert "exceeds the limit" in check.message


# --- DMARC ------------------------------------------------------------------


def test_parse_tags():
    assert parse_tags("v=DMARC1; p=reject ; rua=mailto:a@b.c") == {
        "v": "DMARC1",
        "p": "reject",
        "rua": "mailto:a@b.c",
    }


@pytest.mark.parametrize(
    ("record", "status"),
    [
        ("v=DMARC1; p=reject; rua=mailto:r@d.com", Status.OK),
        ("v=DMARC1; p=quarantine; rua=mailto:r@d.com", Status.OK),
        ("v=DMARC1; p=none; rua=mailto:r@d.com", Status.WARN),
        ("v=DMARC1; p=reject; pct=20", Status.WARN),
        ("v=DMARC1; rua=mailto:r@d.com", Status.FAIL),
    ],
)
def test_dmarc_policies(record, status):
    resolver = FakeResolver(txt={"_dmarc.d.com": [record]})
    assert check_dmarc("d.com", resolver).status is status


def test_dmarc_missing():
    assert check_dmarc("d.com", FakeResolver()).status is Status.FAIL


def test_dmarc_inherited_from_parent_uses_sp():
    resolver = FakeResolver(txt={"_dmarc.d.com": ["v=DMARC1; p=reject; sp=none"]})
    check = check_dmarc("mail.d.com", resolver)
    assert check.status is Status.WARN
    assert "inherited from d.com" in check.message


# --- DKIM / MTA-STS ---------------------------------------------------------


def test_dkim_found(secure_resolver):
    check = check_dkim("example.com", secure_resolver)
    assert check.status is Status.OK
    assert "google" in check.message


def test_dkim_revoked_key_is_ignored():
    resolver = FakeResolver(txt={"default._domainkey.d.com": ["v=DKIM1; p="]})
    assert check_dkim("d.com", resolver).status is Status.INFO


def test_dkim_lookup_errors_are_skipped():
    resolver = FakeResolver(
        txt={"selector1._domainkey.d.com": ["v=DKIM1; p=MIGf"]},
        failing={"google._domainkey.d.com"},
    )
    assert check_dkim("d.com", resolver).status is Status.OK


def test_mta_sts(secure_resolver, empty_resolver):
    assert check_mta_sts("example.com", secure_resolver).status is Status.OK
    assert check_mta_sts("example.com", empty_resolver).status is Status.INFO
