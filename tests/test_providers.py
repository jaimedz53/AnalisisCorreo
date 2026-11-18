import pytest

from mxray.providers import NO_MAIL, UNKNOWN, detect_provider


@pytest.mark.parametrize(
    ("hosts", "expected"),
    [
        (["aspmx.l.google.com"], "Google Workspace / Gmail"),
        (["gmail-smtp-in.l.google.com"], "Google Workspace / Gmail"),
        (["contoso-com.mail.protection.outlook.com"], "Microsoft 365"),
        (["hotmail-com.olc.protection.outlook.com"], "Outlook.com / Hotmail"),
        (["mx01.mail.icloud.com"], "iCloud Mail"),
        (["mta5.am0.yahoodns.net"], "Yahoo"),
        (["europe.mta.mail.yahoo.com"], "Yahoo"),  # yahoo.es
        (["eu-smtp-inbound-1.mimecast.com"], "Mimecast"),
        (["mx0a-001.pphosted.com"], "Proofpoint"),
        (["MX00.IONOS.ES."], "IONOS"),
    ],
)
def test_known_providers(hosts, expected):
    assert detect_provider(hosts).name == expected


def test_uses_first_recognised_host_by_priority():
    hosts = ["mail.mycompany.es", "aspmx.l.google.com"]
    assert detect_provider(hosts).name == "Google Workspace / Gmail"


def test_unknown_and_no_mail():
    assert detect_provider(["mail.mycompany.es"]) is UNKNOWN
    assert detect_provider([]) is NO_MAIL
    assert detect_provider([""]) is NO_MAIL  # null MX


def test_suffix_must_match_whole_label():
    # "notgoogle.com" must not be detected as Google.
    assert detect_provider(["mx.notgoogle.com"]) is UNKNOWN


def test_gateway_kind():
    assert detect_provider(["eu-smtp-inbound-1.mimecast.com"]).kind == "gateway"
