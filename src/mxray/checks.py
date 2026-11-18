"""Individual checks. Each one returns a :class:`Check` and never touches the network directly."""

from __future__ import annotations

import re

from .models import Check, MXRecord, Status, worst
from .resolver import DNSLookupError, Resolver

SPF_LOOKUP_LIMIT = 10  # RFC 7208 section 4.6.4

COMMON_DKIM_SELECTORS: tuple[str, ...] = (
    "google", "selector1", "selector2", "default", "dkim", "mail", "k1", "k2",
    "s1", "s2", "smtp", "mandrill", "mailjet", "sendgrid", "zoho", "protonmail",
    "fm1", "everlytickey1", "mxvault",
)  # fmt: skip


# --------------------------------------------------------------------------- MX


def check_mx(mx: list[MXRecord]) -> Check:
    if not mx:
        return Check(
            "mx",
            Status.FAIL,
            "No MX records: the domain cannot reliably receive email.",
        )
    if len(mx) == 1 and mx[0].host == "":
        return Check(
            "mx",
            Status.INFO,
            "Null MX (RFC 7505): the domain explicitly does not accept email.",
            ".",
        )
    hosts = ", ".join(f"{r.host} ({r.priority})" for r in mx)
    return Check("mx", Status.OK, f"{len(mx)} MX record(s) found.", hosts)


# -------------------------------------------------------------------------- SPF


def find_spf(txts: list[str]) -> list[str]:
    return [t for t in txts if t.lower() == "v=spf1" or t.lower().startswith("v=spf1 ")]


def _lookup_terms(record: str):
    """Yield (kind, target) for every SPF term that costs a DNS lookup."""
    for term in record.split()[1:]:
        t = term.lower().lstrip("+-~?")
        if t.startswith("include:"):
            yield "include", t.split(":", 1)[1]
        elif t.startswith("redirect="):
            yield "redirect", t.split("=", 1)[1]
        elif t in ("a", "mx", "ptr") or t.startswith(("a:", "a/", "mx:", "mx/", "ptr:", "exists:")):
            yield "other", None


def count_spf_lookups(
    record: str, resolver: Resolver, _seen: set[str] | None = None, _depth: int = 0
) -> int:
    """Count DNS-querying mechanisms, following include:/redirect= recursively."""
    seen = _seen if _seen is not None else set()
    total = 0
    for _kind, target in _lookup_terms(record):
        total += 1
        if not target or "%" in target or target in seen or _depth >= 10:
            continue  # macros can't be expanded statically; loops/depth guarded
        seen.add(target)
        try:
            nested = find_spf(resolver.txt(target))
        except DNSLookupError:
            continue
        if nested:
            total += count_spf_lookups(nested[0], resolver, seen, _depth + 1)
    return total


def check_spf(domain: str, resolver: Resolver) -> Check:
    records = find_spf(resolver.txt(domain))
    if not records:
        return Check(
            "spf",
            Status.FAIL,
            "No SPF record: any server can claim to send email for this domain.",
        )
    if len(records) > 1:
        return Check(
            "spf",
            Status.FAIL,
            f"{len(records)} SPF records found; only one is allowed (permerror).",
            " | ".join(records),
        )

    record = records[0]
    terms = record.lower().split()
    all_term = next((t for t in terms if t.lstrip("+-~?") == "all"), None)
    has_redirect = any(t.startswith("redirect=") for t in terms)
    lookups = count_spf_lookups(record, resolver)

    statuses: list[Status] = [Status.OK]
    notes: list[str] = []
    if all_term in ("all", "+all"):
        statuses.append(Status.FAIL)
        notes.append("'+all' authorizes every server on the Internet")
    elif all_term == "?all":
        statuses.append(Status.WARN)
        notes.append("'?all' is neutral and gives no protection")
    elif all_term is None and not has_redirect:
        statuses.append(Status.WARN)
        notes.append("no 'all' mechanism at the end")
    if lookups > SPF_LOOKUP_LIMIT:
        statuses.append(Status.FAIL)
        notes.append(f"{lookups} DNS lookups exceeds the limit of {SPF_LOOKUP_LIMIT} (permerror)")

    status = worst(*statuses)
    if status is Status.OK:
        policy = all_term or "redirect"
        message = f"Valid SPF ({policy}, {lookups}/{SPF_LOOKUP_LIMIT} DNS lookups)."
    else:
        message = "SPF problems: " + "; ".join(notes) + "."
    return Check("spf", status, message, record)


# ------------------------------------------------------------------------ DMARC


def parse_tags(record: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for part in record.split(";"):
        if "=" in part:
            key, value = part.split("=", 1)
            tags[key.strip().lower()] = value.strip()
    return tags


def _find_dmarc(name: str, resolver: Resolver) -> list[str]:
    txts = resolver.txt(f"_dmarc.{name}")
    return [t for t in txts if t.replace(" ", "").lower().startswith("v=dmarc1")]


def check_dmarc(domain: str, resolver: Resolver) -> Check:
    # Subdomains without their own record inherit the parent's policy (RFC 7489 6.6.3).
    # We walk up the labels as a simple approximation of the "organizational domain".
    labels = domain.split(".")
    found_at, records = domain, []
    for i in range(len(labels) - 1):
        candidate = ".".join(labels[i:])
        records = _find_dmarc(candidate, resolver)
        if records:
            found_at = candidate
            break

    if not records:
        return Check(
            "dmarc",
            Status.FAIL,
            "No DMARC record: receivers get no instructions for spoofed email.",
        )
    if len(records) > 1:
        return Check("dmarc", Status.FAIL, "Multiple DMARC records found.", " | ".join(records))

    record = records[0]
    tags = parse_tags(record)
    inherited = found_at != domain
    policy = (tags.get("sp") if inherited and "sp" in tags else tags.get("p", "")).lower()

    notes: list[str] = []
    if policy in ("reject", "quarantine"):
        status = Status.OK
    elif policy == "none":
        status = Status.WARN
        notes.append("the 'none' policy only monitors, spoofed email is still delivered")
    else:
        status = Status.FAIL
        notes.append(f"invalid or missing policy ({policy or 'empty'})")

    pct = tags.get("pct")
    if pct and pct != "100":
        status = worst(status, Status.WARN)
        notes.append(f"the policy only applies to {pct}% of the email (pct={pct})")
    if "rua" not in tags:
        notes.append("no rua= tag, so no aggregate reports are received")
    if inherited:
        notes.append(f"inherited from {found_at}")

    message = f"DMARC policy: {policy or '-'}."
    if notes:
        text = "; ".join(notes)
        message += f" {text[0].upper()}{text[1:]}."
    return Check("dmarc", status, message, record)


# ------------------------------------------------------------------------- DKIM

_EMPTY_KEY = re.compile(r"(^|;)\s*p=\s*(;|$)")
_HAS_KEY = re.compile(r"(^|;)\s*p=\S")


def check_dkim(
    domain: str, resolver: Resolver, selectors: tuple[str, ...] = COMMON_DKIM_SELECTORS
) -> Check:
    found: list[str] = []
    for selector in selectors:
        try:
            txts = resolver.txt(f"{selector}._domainkey.{domain}")
        except DNSLookupError:
            continue
        for txt in txts:
            if _HAS_KEY.search(txt) and not _EMPTY_KEY.search(txt):
                found.append(selector)
                break
    if found:
        return Check(
            "dkim",
            Status.OK,
            f"DKIM key published for selector(s): {', '.join(found)}.",
            ", ".join(f"{s}._domainkey.{domain}" for s in found),
        )
    return Check(
        "dkim",
        Status.INFO,
        "No DKIM key found on common selectors. Selectors can't be listed through DNS, "
        "so DKIM may still be configured with a custom one.",
    )


# ---------------------------------------------------------------------- MTA-STS


def check_mta_sts(domain: str, resolver: Resolver) -> Check:
    records = [t for t in resolver.txt(f"_mta-sts.{domain}") if t.lower().startswith("v=stsv1")]
    if records:
        return Check("mta-sts", Status.OK, "MTA-STS is enabled (TLS enforced).", records[0])
    return Check("mta-sts", Status.INFO, "MTA-STS not configured (optional, recommended).")
