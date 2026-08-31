from redhunt import osint


def test_all_50_osint_executors_return_normalized_results(monkeypatch):
    def fake_fetch(url, timeout=10):
        return {
            "status": 200,
            "url": url,
            "headers": {"Content-Type": "text/html", "Server": "fixture"},
            "body": '<html><script src="/app.js"></script><a href="https://example.test/api">API</a></html>',
        }

    monkeypatch.setattr(osint, "fetch", fake_fetch)
    results = osint.osint_run("https://example.test", context={"ips": ["127.0.0.1"], "ct": ["api.example.test"], "body": fake_fetch("")["body"], "headers": fake_fetch("")["headers"], "tls": {"status": "DETECTED"}, "technology": {"observed": {"server": "fixture"}}, "cloud": {}, "robots": {}, "sitemap": {}, "api": {}, "security_txt": {}})
    assert len(results) == 50
    assert [item["id"] for item in results] == [f"OS-{i:02d}" for i in range(1, 51)]
    assert all(item["status"] in {"DETECTED", "NOT DETECTED", "INCONCLUSIVE", "SKIPPED", "NOT TESTED"} for item in results)
    assert all("evidence" in item for item in results)
