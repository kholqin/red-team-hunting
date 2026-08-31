import redhunt.bugbounty as bb
import redhunt.cli as cli


def test_all_50_bugbounty_records_are_executable_with_local_context(monkeypatch):
    response = (200, {"Content-Type": "text/html"}, "<html><a href='/api'>api</a></html>", 0.01)
    monkeypatch.setattr(cli, "request", lambda *args, **kwargs: response)
    monkeypatch.setattr(cli, "dns", lambda *args, **kwargs: {"host": "localhost", "ips": ["127.0.0.1"]})
    monkeypatch.setattr(cli, "headers", lambda *args, **kwargs: {"status": 200, "missing_security_headers": []})
    monkeypatch.setattr(cli, "endpoints", lambda *args, **kwargs: {"status": 200, "endpoints": ["/api"]})
    monkeypatch.setattr(cli, "vuln_check", lambda *args, **kwargs: {"status": "NOT DETECTED", "findings": []})
    monkeypatch.setattr(bb, "ct_subdomains", lambda *args, **kwargs: {"subdomains": []})
    monkeypatch.setattr(bb, "tls_audit", lambda *args, **kwargs: {"status": "DETECTED"})
    monkeypatch.setattr(bb, "robots_and_sitemap", lambda *args, **kwargs: {"robots": {"status": 404}, "sitemap": {"status": 404}})
    monkeypatch.setattr(bb, "technology", lambda *args, **kwargs: {"observed": {}})
    monkeypatch.setattr(bb, "cookie_audit", lambda *args, **kwargs: {"cookies": []})
    monkeypatch.setattr(bb, "cors_audit", lambda *args, **kwargs: {"allow_origin": None})
    monkeypatch.setattr(bb, "safe_web_indicators", lambda *args, **kwargs: {"findings": []})
    monkeypatch.setattr(bb, "api_document_analysis", lambda *args, **kwargs: {"documents": [], "graphql": {"status": 404}})
    monkeypatch.setattr(bb, "cloud_fingerprint", lambda *args, **kwargs: {"providers": [], "public_storage_references": [], "metadata_references": []})
    records = bb.run_bug_bounty("http://localhost:18080", {"timeout": 1, "concurrency": 2})
    assert len(records) == 50
    assert [r["id"] for r in records] == [f"BB-{i:02d}" for i in range(1, 51)]
    assert all(r["status"] in {"DETECTED", "NOT DETECTED", "INCONCLUSIVE", "SKIPPED", "NOT TESTED"} for r in records)
    assert all("evidence" in r for r in records)
