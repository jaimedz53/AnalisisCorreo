"""Command line interface: ``mxray check``, ``mxray batch`` and ``mxray serve``."""

from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from .audit import audit_domain, audit_many, normalize_domain
from .models import DomainReport, Status
from .resolver import DnsPythonResolver

app = typer.Typer(
    help="Audit the email setup of a domain: provider, MX, SPF, DKIM, DMARC and MTA-STS.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()

STATUS_STYLE = {Status.OK: "green", Status.WARN: "yellow", Status.FAIL: "red", Status.INFO: "cyan"}
RISK_STYLE = {"low": "green", "medium": "yellow", "high": "red"}


def _status(status: Status) -> str:
    return f"[{STATUS_STYLE[status]}]{status.value.upper()}[/]"


def _risk(risk: str) -> str:
    return f"[{RISK_STYLE[risk]}]{risk}[/]"


def print_report(report: DomainReport) -> None:
    console.print(
        f"\n[bold]{report.domain}[/]  provider: [bold]{report.provider}[/] "
        f"({report.provider_kind})  score: [bold]{report.score}/100[/]  "
        f"risk: {_risk(report.risk)}\n"
    )
    table = Table(show_header=True, header_style="bold", expand=True)
    table.add_column("Check", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Details")
    for check in report.checks:
        details = check.message
        if check.record:
            details += f"\n[dim]{check.record}[/]"
        table.add_row(check.name.upper(), _status(check.status), details)
    console.print(table)


@app.command()
def check(
    domain: str = typer.Argument(..., help="Domain, email address or URL."),
    as_json: bool = typer.Option(False, "--json", help="Print the report as JSON."),
    timeout: float = typer.Option(5.0, help="DNS timeout in seconds."),
    fail_under: int | None = typer.Option(
        None, help="Exit with code 1 if the score is below this value (useful in CI)."
    ),
) -> None:
    """Audit a single domain."""
    try:
        report = audit_domain(domain, DnsPythonResolver(timeout=timeout))
    except ValueError as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(2) from exc

    if as_json:
        typer.echo(json.dumps(report.to_dict(), indent=2))
    else:
        print_report(report)

    if fail_under is not None and report.score < fail_under:
        raise typer.Exit(1)


def read_inputs(path: Path, column: str | None) -> list[str]:
    """Read emails/domains from a .csv (one column) or a plain text file (one per line)."""
    text = path.read_text(encoding="utf-8-sig")
    if path.suffix.lower() != ".csv":
        return [
            line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")
        ]

    rows = [row for row in csv.reader(text.splitlines()) if row]
    if not rows:
        return []
    if column:
        header = [h.strip() for h in rows[0]]
        if column not in header:
            raise typer.BadParameter(f"Column {column!r} not found. Available: {header}")
        idx = header.index(column)
        return [row[idx].strip() for row in rows[1:] if len(row) > idx and row[idx].strip()]

    values = [row[0].strip() for row in rows if row[0].strip()]
    # Skip a header row like "email" when no column name was given.
    if values:
        try:
            normalize_domain(values[0])
        except ValueError:
            values = values[1:]
    return values


@app.command()
def batch(
    file: Path = typer.Argument(..., exists=True, dir_okay=False, help="CSV or text file."),
    column: str | None = typer.Option(None, help="CSV column with the emails/domains."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write results to a CSV."),
    workers: int = typer.Option(8, help="Concurrent DNS workers."),
    timeout: float = typer.Option(5.0, help="DNS timeout in seconds."),
) -> None:
    """Audit every domain found in a list of emails or domains."""
    values = read_inputs(file, column)
    pairs: list[tuple[str, str | None]] = []
    for value in values:
        try:
            pairs.append((value, normalize_domain(value)))
        except ValueError:
            pairs.append((value, None))

    domains = [d for _, d in pairs if d]
    with console.status(f"Auditing {len(set(domains))} domain(s)..."):
        reports = audit_many(domains, DnsPythonResolver(timeout=timeout), workers=workers)

    per_domain = Counter(domains)
    table = Table(title="Domains", header_style="bold")
    for col in ("Domain", "Inputs", "Provider", "SPF", "DMARC", "DKIM", "Score", "Risk"):
        table.add_column(col)
    for domain, report in sorted(reports.items(), key=lambda kv: kv[1].score):
        table.add_row(
            domain,
            str(per_domain[domain]),
            report.provider,
            *(_status(report.get(n).status) for n in ("spf", "dmarc", "dkim")),
            str(report.score),
            _risk(report.risk),
        )
    console.print(table)

    providers = Counter(reports[d].provider for d in domains)
    summary = Table(title="Inputs per provider", header_style="bold")
    summary.add_column("Provider")
    summary.add_column("Inputs", justify="right")
    summary.add_column("%", justify="right")
    for provider, count in providers.most_common():
        summary.add_row(provider, str(count), f"{100 * count / len(domains):.1f}")
    console.print(summary)

    invalid = [v for v, d in pairs if d is None]
    if invalid:
        preview = ", ".join(invalid[:10])
        console.print(f"[yellow]{len(invalid)} invalid input(s) skipped:[/] {preview}")

    if output:
        with output.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(
                ["input", "domain", "provider", "provider_kind", "score", "risk",
                 "mx", "spf", "dmarc", "dkim", "mta_sts"]
            )  # fmt: skip
            for value, domain in pairs:
                if domain is None:
                    writer.writerow([value, "", "", "", "", "invalid"] + [""] * 5)
                    continue
                r = reports[domain]
                writer.writerow(
                    [value, domain, r.provider, r.provider_kind, r.score, r.risk]
                    + [c.status.value for c in r.checks]
                )
        console.print(f"Results written to [bold]{output}[/]")


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", help="Bind address."),
    port: int = typer.Option(8000, help="Port."),
) -> None:
    """Start the REST API (requires the 'api' extra)."""
    try:
        import uvicorn
    except ImportError as exc:
        console.print('[red]Install the API extra first:[/] pip install "mxray[api]"')
        raise typer.Exit(1) from exc
    uvicorn.run("mxray.api:app", host=host, port=port)


def main() -> None:
    app()
