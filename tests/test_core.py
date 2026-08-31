import json
from pathlib import Path

from redhunt.cli import in_scope, normalize_target, reverse


def test_normalize_hostname():
    assert normalize_target("example.com") == "https://example.com"


def test_reject_invalid_target():
    try:
        normalize_target("not a target\n")
    except ValueError:
        return
    assert False, "target tidak valid harus ditolak"


def test_scope_enforcement(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    Path("scope.json").write_text(json.dumps({"allowed": ["example.com", "*.example.com"], "excluded": ["admin.example.com"]}))
    assert in_scope("https://example.com", {"scope_enforcement": True})
    assert in_scope("https://api.example.com", {"scope_enforcement": True})
    assert not in_scope("https://admin.example.com", {"scope_enforcement": True})
    assert not in_scope("https://other.test", {"scope_enforcement": True})


def test_reverse_hash_and_type(tmp_path):
    p = tmp_path / "sample.bin"
    p.write_bytes(b"hello world\x00API_KEY=redacted")
    result = reverse(str(p))
    assert result["type"] == "unknown"
    assert len(result["hashes"]["sha256"]) == 64
    assert "API_KEY" in result["secret_indicators"]


def test_scope_disabled(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    Path("scope.json").write_text(json.dumps({"allowed": [], "excluded": []}))
    assert in_scope("https://outside.test", {"scope_enforcement": False})
