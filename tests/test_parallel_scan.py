import json
from pathlib import Path

import pytest

from scripts.parallel_scan import in_scope, load_scope, normalize_target, read_targets


def test_normalize_target_rejects_query_and_credentials():
    assert normalize_target("example.com") == "https://example.com"
    with pytest.raises(ValueError): normalize_target("https://user:pass@example.com")
    with pytest.raises(ValueError): normalize_target("https://example.com/?q=1")


def test_scope_and_target_file(tmp_path):
    scope = tmp_path / "scope.json"
    scope.write_text(json.dumps({"allowed": ["example.com"]}), encoding="utf-8")
    targets = tmp_path / "targets.txt"
    targets.write_text("example.com\n# comment\nhttps://sub.example.com\n", encoding="utf-8")
    allowed = load_scope(scope)
    assert in_scope("https://sub.example.com", allowed)
    assert read_targets(targets, allowed, 10) == ["https://example.com", "https://sub.example.com"]


def test_out_of_scope_target_is_rejected(tmp_path):
    scope = tmp_path / "scope.json"
    scope.write_text(json.dumps({"allowed": ["example.com"]}), encoding="utf-8")
    targets = tmp_path / "targets.txt"
    targets.write_text("not-example.com\n", encoding="utf-8")
    with pytest.raises(ValueError, match="outside scope"):
        read_targets(targets, load_scope(scope), 10)
