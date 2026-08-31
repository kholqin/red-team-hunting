from pathlib import Path

from redhunt.language import analyze_file, detect_language


def test_language_extension_map():
    assert detect_language(Path("main.py")) == "Python"
    assert detect_language(Path("app.ts")) == "TypeScript"
    assert detect_language(Path("Contract.sol")) == "Solidity"
    assert detect_language(Path("main.rs")) == "Rust"
    assert detect_language(Path("query.sql")) == "SQL"


def test_source_secret_is_redacted(tmp_path):
    source = tmp_path / "config.py"
    source.write_text("API_KEY = 'super-secret-value-123'\nsubprocess.run(cmd)\n", encoding="utf-8")
    result = analyze_file(str(source))
    assert result["status"] == "COMPLETED"
    assert result["language"] == "Python"
    assert result["finding_count"] >= 2
    assert all("super-secret-value-123" not in item["evidence"] for item in result["findings"])


def test_unknown_file_is_not_claimed_as_language(tmp_path):
    source = tmp_path / "file.unknown"
    source.write_text("plain text", encoding="utf-8")
    assert analyze_file(str(source))["language"] == "Unknown"
