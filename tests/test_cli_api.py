import csv
import json

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from mxray import api, cli


@pytest.fixture
def patched(monkeypatch, secure_resolver):
    """Make the CLI use the fake resolver instead of real DNS."""
    monkeypatch.setattr(cli, "DnsPythonResolver", lambda timeout=5.0: secure_resolver)
    return secure_resolver


runner = CliRunner()


def test_check_json(patched):
    result = runner.invoke(cli.app, ["check", "example.com", "--json"])
    assert result.exit_code == 0
    assert json.loads(result.output)["score"] == 100


def test_check_fail_under(monkeypatch, empty_resolver):
    monkeypatch.setattr(cli, "DnsPythonResolver", lambda timeout=5.0: empty_resolver)
    result = runner.invoke(cli.app, ["check", "example.com", "--fail-under", "80"])
    assert result.exit_code == 1


def test_check_invalid_domain(patched):
    result = runner.invoke(cli.app, ["check", "nope"])
    assert result.exit_code == 2


def test_batch_csv_with_header(patched, tmp_path):
    src = tmp_path / "emails.csv"
    src.write_text("name,email\nAna,ana@example.com\nLuis,luis@example.com\nX,bad\n")
    out = tmp_path / "out.csv"

    result = runner.invoke(cli.app, ["batch", str(src), "--column", "email", "-o", str(out)])

    assert result.exit_code == 0, result.output
    rows = list(csv.DictReader(out.open()))
    assert [r["domain"] for r in rows] == ["example.com", "example.com", ""]
    assert rows[0]["provider"] == "Google Workspace / Gmail"
    assert rows[2]["risk"] == "invalid"


def test_read_inputs_skips_header_and_comments(tmp_path):
    csv_file = tmp_path / "a.csv"
    csv_file.write_text("email\nana@example.com\n")
    txt_file = tmp_path / "a.txt"
    txt_file.write_text("# comment\nexample.com\n\nother.com\n")
    assert cli.read_inputs(csv_file, None) == ["ana@example.com"]
    assert cli.read_inputs(txt_file, None) == ["example.com", "other.com"]


@pytest.fixture
def client(secure_resolver):
    api.app.dependency_overrides[api.get_resolver] = lambda: secure_resolver
    yield TestClient(api.app)
    api.app.dependency_overrides.clear()


def test_api_single_domain(client):
    response = client.get("/domains/example.com")
    assert response.status_code == 200
    assert response.json()["provider"] == "Google Workspace / Gmail"


def test_api_invalid_domain(client):
    assert client.get("/domains/nope").status_code == 422


def test_api_batch(client):
    response = client.post("/audit", json={"domains": ["a@example.com", "bad"]})
    body = response.json()
    assert response.status_code == 200
    assert [r["domain"] for r in body["results"]] == ["example.com"]
    assert body["invalid"] == ["bad"]
