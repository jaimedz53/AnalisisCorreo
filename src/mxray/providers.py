"""Identify the email provider of a domain from its MX hosts."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Provider:
    name: str
    kind: str  # "mailbox", "gateway" (security filter in front of the mailbox), "unknown", "none"
    patterns: tuple[str, ...] = ()

    def matches(self, host: str) -> bool:
        return any(host == p or host.endswith("." + p) for p in self.patterns)


# Order matters: more specific patterns must come before broader ones.
PROVIDERS: tuple[Provider, ...] = (
    Provider("Outlook.com / Hotmail", "mailbox", ("olc.protection.outlook.com",)),
    Provider("Microsoft 365", "mailbox", ("mail.protection.outlook.com", "outlook.com")),
    Provider("Google Workspace / Gmail", "mailbox", ("google.com", "googlemail.com")),
    Provider("Yahoo", "mailbox", ("yahoodns.net", "yahoo.com")),
    Provider("Zoho Mail", "mailbox", ("zoho.com", "zoho.eu", "zoho.in")),
    Provider("Proton Mail", "mailbox", ("protonmail.ch", "proton.me")),
    Provider("iCloud Mail", "mailbox", ("icloud.com",)),
    Provider("Fastmail", "mailbox", ("messagingengine.com",)),
    Provider("Yandex Mail", "mailbox", ("yandex.net", "yandex.ru")),
    Provider("GMX / Web.de", "mailbox", ("gmx.net", "gmx.com", "web.de")),
    Provider("Amazon WorkMail / SES", "mailbox", ("amazonaws.com",)),
    Provider("OVHcloud", "mailbox", ("ovh.net",)),
    Provider("IONOS", "mailbox", ("ionos.es", "ionos.com", "ionos.de", "kundenserver.de")),
    Provider("GoDaddy", "mailbox", ("secureserver.net",)),
    Provider("Hostinger", "mailbox", ("hostinger.com",)),
    Provider("Mimecast", "gateway", ("mimecast.com", "mimecast.co.za")),
    Provider("Proofpoint", "gateway", ("pphosted.com", "ppe-hosted.com")),
    Provider("Barracuda", "gateway", ("barracudanetworks.com",)),
    Provider("Cisco Secure Email", "gateway", ("iphmx.com",)),
    Provider("Trend Micro", "gateway", ("tmes.trendmicro.com", "tmes.trendmicro.eu")),
)

UNKNOWN = Provider("Unknown / self-hosted", "unknown")
NO_MAIL = Provider("No mail server", "none")


def match_host(host: str) -> Provider | None:
    host = host.lower().rstrip(".")
    return next((p for p in PROVIDERS if p.matches(host)), None)


def detect_provider(mx_hosts: list[str]) -> Provider:
    """``mx_hosts`` must be sorted by priority (most preferred first)."""
    hosts = [h for h in mx_hosts if h]  # drop null MX ("")
    if not hosts:
        return NO_MAIL
    for host in hosts:
        provider = match_host(host)
        if provider:
            return provider
    return UNKNOWN
