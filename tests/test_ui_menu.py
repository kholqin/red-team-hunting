from redhunt.catalog import FEATURES
from redhunt.ui import feature_from_choice


def test_numeric_menu_mapping_covers_all_features():
    assert len(FEATURES) == 120
    assert feature_from_choice("001").id == "BB-01"
    assert feature_from_choice("050").id == "BB-50"
    assert feature_from_choice("051").id == "OS-01"
    assert feature_from_choice("100").id == "OS-50"
    assert feature_from_choice("101").id == "RE-01"
    assert feature_from_choice("120").id == "RE-20"
    assert feature_from_choice("121") is None


def test_legacy_feature_id_mapping_is_preserved():
    assert feature_from_choice("BB-01").id == "BB-01"
    assert feature_from_choice("os-50").id == "OS-50"
    assert feature_from_choice("RE-20").id == "RE-20"
