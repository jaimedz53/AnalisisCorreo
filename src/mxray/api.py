"""REST API. Run with ``mxray serve`` and open http://127.0.0.1:8000/docs."""

from __future__ import annotations

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, Field

from . import __version__
from .audit import audit_domain, audit_many, normalize_domain
from .resolver import DnsPythonResolver, Resolver

app = FastAPI(
    title="mxray",
    version=__version__,
    description="Detect the email provider of a domain and audit MX, SPF, DKIM, DMARC and MTA-STS.",
)


def get_resolver() -> Resolver:
    return DnsPythonResolver()


class BatchRequest(BaseModel):
    domains: list[str] = Field(..., min_length=1, max_length=100, examples=[["gmail.com"]])


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "version": __version__}


@app.get("/domains/{domain}")
def get_domain(domain: str, resolver: Resolver = Depends(get_resolver)) -> dict:
    try:
        return audit_domain(domain, resolver).to_dict()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/audit")
def audit(request: BatchRequest, resolver: Resolver = Depends(get_resolver)) -> dict:
    valid, invalid = [], []
    for value in request.domains:
        try:
            valid.append(normalize_domain(value))
        except ValueError:
            invalid.append(value)
    reports = audit_many(valid, resolver)
    return {"results": [r.to_dict() for r in reports.values()], "invalid": invalid}
