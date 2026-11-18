"""Run every check on a domain and compute a 0-100 score."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

from .checks import check_dkim, check_dmarc, check_mta_sts, check_mx, check_spf
from .models import Check, DomainReport, MXRecord, Status
from .providers import detect_provider
from .resolver import DNSLookupError, DnsPythonResolver, Resolver

WEIGHTS: dict[str, int] = {"mx": 20, "spf": 30, "dmarc": 35, "dkim": 15, "mta-sts": 0}
FACTOR: dict[Status, float] = {Status.OK: 1.0, Status.WARN: 0.5, Status.INFO: 0.5, Status.FAIL: 0.0}


def normalize_domain(value: str) -> str:
    """Accept a domain, an email address or a URL and return an ASCII domain."""
    v = value.strip().lower()
    if "://" in v:
        v = urlsplit(v).hostname or ""
    if "@" in v:
        v = v.rsplit("@", 1)[1]
    v = v.split("/", 1)[0].strip().strip(".")
    if not v or "." not in v or any(c.isspace() for c in v):
        raise ValueError(f"Not a valid domain or email: {value!r}")
    try:
        return v.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"Not a valid domain or email: {value!r}") from exc


def compute_score(checks: list[Check]) -> int:
    return round(sum(WEIGHTS.get(c.name, 0) * FACTOR[c.status] for c in checks))


def _safe(name: str, fn: Callable[[], Check]) -> Check:
    try:
        return fn()
    except DNSLookupError as exc:
        return Check(name, Status.WARN, f"DNS lookup failed: {exc}.")


def audit_domain(domain: str, resolver: Resolver | None = None) -> DomainReport:
    resolver = resolver or DnsPythonResolver()
    domain = normalize_domain(domain)

    try:
        mx = [MXRecord(priority, host) for priority, host in resolver.mx(domain)]
        mx_check = check_mx(mx)
    except DNSLookupError as exc:
        mx, mx_check = [], Check("mx", Status.WARN, f"DNS lookup failed: {exc}.")

    provider = detect_provider([r.host for r in mx])
    checks = [
        mx_check,
        _safe("spf", lambda: check_spf(domain, resolver)),
        _safe("dmarc", lambda: check_dmarc(domain, resolver)),
        _safe("dkim", lambda: check_dkim(domain, resolver)),
        _safe("mta-sts", lambda: check_mta_sts(domain, resolver)),
    ]
    return DomainReport(
        domain=domain,
        provider=provider.name,
        provider_kind=provider.kind,
        mx=mx,
        checks=checks,
        score=compute_score(checks),
    )


def audit_many(
    domains: Iterable[str], resolver: Resolver | None = None, workers: int = 8
) -> dict[str, DomainReport]:
    """Audit several (already normalized) domains concurrently, once per unique domain."""
    resolver = resolver or DnsPythonResolver()
    unique = list(dict.fromkeys(domains))
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        reports = list(pool.map(lambda d: audit_domain(d, resolver), unique))
    return dict(zip(unique, reports, strict=True))
