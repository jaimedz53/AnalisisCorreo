"""mxray: audit the email setup of any domain."""

from .audit import audit_domain, audit_many, normalize_domain
from .models import Check, DomainReport, MXRecord, Status

__version__ = "0.1.0"

__all__ = [
    "Check",
    "DomainReport",
    "MXRecord",
    "Status",
    "audit_domain",
    "audit_many",
    "normalize_domain",
]
