"""DNS access behind a tiny interface, so checks can be tested without network."""

from __future__ import annotations

from typing import Protocol

import dns.exception
import dns.resolver


class DNSLookupError(Exception):
    """The lookup could not be completed (timeout, SERVFAIL...).

    A domain or record that simply does not exist is *not* an error:
    resolvers return an empty list in that case.
    """


class Resolver(Protocol):
    def mx(self, domain: str) -> list[tuple[int, str]]:
        """Return (priority, host) pairs sorted by priority. Null MX host is ''."""
        ...

    def txt(self, name: str) -> list[str]:
        """Return every TXT record of ``name`` as a single joined string."""
        ...


class DnsPythonResolver:
    """Real resolver backed by dnspython."""

    def __init__(self, timeout: float = 5.0, nameservers: list[str] | None = None) -> None:
        self._resolver = dns.resolver.Resolver()
        self._resolver.lifetime = timeout
        if nameservers:
            self._resolver.nameservers = nameservers

    def _query(self, name: str, rtype: str):
        try:
            return self._resolver.resolve(name, rtype)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except dns.resolver.NoNameservers as exc:
            raise DNSLookupError(f"no nameserver answered {rtype} {name}") from exc
        except dns.exception.Timeout as exc:
            raise DNSLookupError(f"timeout resolving {rtype} {name}") from exc

    def mx(self, domain: str) -> list[tuple[int, str]]:
        answers = self._query(domain, "MX")
        return sorted((r.preference, r.exchange.to_text().rstrip(".").lower()) for r in answers)

    def txt(self, name: str) -> list[str]:
        return [
            b"".join(r.strings).decode("utf-8", errors="replace") for r in self._query(name, "TXT")
        ]
