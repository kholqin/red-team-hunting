from redhunt.catalog import catalog, counts


def test_catalog_has_requested_120_features():
    assert len(catalog()) == 120
    totals = counts()
    assert totals["BUG_BOUNTY"]["total"] == 50
    assert totals["OSINT"]["total"] == 50
    assert totals["REVERSE"]["total"] == 20


def test_catalog_ids_are_unique():
    ids = [item["id"] for item in catalog()]
    assert len(ids) == len(set(ids))
