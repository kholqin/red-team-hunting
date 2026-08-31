from __future__ import annotations

import time
from collections.abc import Callable


def run_passes(scan: Callable[[], dict], *, passes: int = 3, delay: float = 0.5, key: str = "fingerprint") -> dict:
    passes=max(2,min(int(passes),5))
    delay=max(0.0,min(float(delay),30.0))
    observations=[]
    for index in range(passes):
        started=time.time()
        try:
            item=scan()
            observations.append({"pass":index+1,"status":"SELESAI","elapsed":round(time.time()-started,3),"observation":item})
        except Exception as exc:
            observations.append({"pass":index+1,"status":"GALAT","elapsed":round(time.time()-started,3),"error":str(exc)})
        if index+1<passes and delay: time.sleep(delay)
    values=[row.get("observation",{}).get(key) for row in observations if row.get("status")=="SELESAI"]
    if len(values)<2:
        validation="BELUM KONKLUSIF"
        internal_status="INCONCLUSIVE"
        reason="kurang dari dua pass berhasil"
    elif all(value==values[0] for value in values):
        validation="TERVERIFIKASI"
        internal_status="VERIFIED"
        reason="fingerprint evidence konsisten pada seluruh pass berhasil"
    else:
        validation="TIDAK KONSISTEN"
        internal_status="INCONCLUSIVE"
        reason="fingerprint evidence berbeda antar-pass"
    return {"jumlah_pass":passes,"pass_berhasil":len(values),"status":internal_status,"validasi":validation,"alasan":reason,"pass":observations}
