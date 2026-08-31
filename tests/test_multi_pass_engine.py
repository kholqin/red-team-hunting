from redhunt.multi_pass import run_passes


def test_consistent():
    result=run_passes(lambda: {"fingerprint":"same"}, passes=3)
    assert result["status"] == "VERIFIED"
    assert result["validasi"] == "TERVERIFIKASI"


def test_inconsistent():
    values=iter(["a","b","a"])
    result=run_passes(lambda: {"fingerprint":next(values)}, passes=3)
    assert result["status"] == "INCONCLUSIVE"
    assert result["validasi"] == "TIDAK KONSISTEN"


def test_failed_pass_is_not_verified():
    def scan():
        raise RuntimeError("simulated transport failure")
    result=run_passes(scan, passes=3)
    assert result["status"] == "INCONCLUSIVE"
    assert result["validasi"] == "BELUM KONKLUSIF"
