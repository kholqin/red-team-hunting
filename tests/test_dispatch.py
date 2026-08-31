import pytest

from redhunt.dispatch import execute


def test_all_feature_ids_have_dispatch_path():
    for index in range(1, 51):
        item = execute(f"BB-{index:02d}")
        assert item["id"] == f"BB-{index:02d}"
        assert item["status"] in {"INCONCLUSIVE", "SKIPPED", "NOT TESTED"}
    for index in range(1, 51):
        item = execute(f"OS-{index:02d}")
        assert item["id"] == f"OS-{index:02d}"
    for index in range(1, 21):
        item = execute(f"RE-{index:02d}")
        assert item["id"] == f"RE-{index:02d}"


def test_unknown_feature_is_rejected():
    with pytest.raises(ValueError):
        execute("XX-99")
