import json

from redhunt.cve_catalog import _db, _normal, correlate, search, stats


def seed_cve(path):
    item={
        "cve": {
            "id":"CVE-2099-1234",
            "published":"2099-01-01T00:00:00.000",
            "lastModified":"2099-01-02T00:00:00.000",
            "descriptions":[{"lang":"en","value":"Example server vulnerability."}],
            "metrics":{"cvssMetric31":[{"cvssData":{"baseSeverity":"HIGH","baseScore":8.1}}]},
            "references":[{"url":"https://example.invalid/advisory"}],
            "configurations":[{"nodes":[{"cpeMatch":[{"criteria":"cpe:2.3:a:example:server:1.2.3:*:*:*:*:*:*:*","vulnerable":True}]}]}]
        }
    }
    db=_db(path)
    db.execute("INSERT OR REPLACE INTO cves VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", _normal(item,set()))
    db.commit(); db.close()


def test_cve_search_and_exact_version_correlation(tmp_path):
    path=tmp_path/"cve.db"
    seed_cve(path)
    assert stats(path)["records"] == 1
    assert search(path,"example server",10)[0]["cve_id"] == "CVE-2099-1234"
    result=correlate(path,{"product":"server","version":"1.2.3"})
    assert result["status"] == "DETECTED"
    assert result["verified_matches"][0]["cve_id"] == "CVE-2099-1234"


def test_product_without_exact_version_is_inconclusive(tmp_path):
    path=tmp_path/"cve.db"
    seed_cve(path)
    result=correlate(path,{"product":"server","version":"9.9.9"})
    assert result["status"] == "INCONCLUSIVE"
    assert result["candidate_matches"]
