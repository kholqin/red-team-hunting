from __future__ import annotations

from pathlib import Path
from .catalog import FEATURES


def _unsupported(feature, reason):
    return {"id":feature.id,"name":feature.name,"category":feature.category,"status":"INCONCLUSIVE","data":{},"evidence":{"reason":reason,"executor":feature.executor}}


def execute(feature_id, *, target=None, path=None, cfg=None):
    """Dispatch exactly one catalog feature; never fabricates a finding."""
    feature=next((f for f in FEATURES if f.id.upper()==feature_id.upper()),None)
    if feature is None: raise ValueError(f"unknown feature id: {feature_id}")
    if feature.category=="BUG_BOUNTY":
        if not target: return _unsupported(feature,"target HTTP(S) diperlukan")
        from .bugbounty import run_bug_bounty
        item=next(x for x in run_bug_bounty(target,cfg or {"timeout":10,"retries":1}) if x["id"]==feature.id)
        return {**item,"category":feature.category,"executor":feature.executor}
    if feature.category=="OSINT":
        if not target: return _unsupported(feature,"target HTTP(S) diperlukan")
        from .osint import osint_run
        item=next(x for x in osint_run(target,(cfg or {}).get("timeout",10)) if x["id"]==feature.id)
        return {**item,"category":feature.category,"executor":feature.executor}
    if feature.category=="REVERSE":
        if not path: return _unsupported(feature,"path file binary/source diperlukan")
        file_path=Path(path)
        if not file_path.is_file(): return _unsupported(feature,"path bukan file regular")
        from .language import analyze_file
        analysis=analyze_file(str(file_path))
        supported={"RE-01":"file_type","RE-02":"hashes","RE-03":"strings","RE-04":"entropy","RE-05":"binary_header","RE-13":"imports","RE-14":"exports","RE-16":"symbols","RE-17":"urls","RE-18":"ips","RE-19":"secret_indicators","RE-20":"risk_indicators"}
        key=supported.get(feature.id)
        if key is None: return _unsupported(feature,"format khusus memerlukan parser binary yang sesuai; tidak menebak hasil")
        return {"id":feature.id,"name":feature.name,"category":feature.category,"status":"DETECTED" if analysis.get(key) else "NOT DETECTED","data":analysis.get(key),"evidence":{"source":"static file analysis aktual","path":str(file_path),"sha256":analysis.get("sha256"),"executor":feature.executor}}
    return _unsupported(feature,"kategori tidak dikenal")


def execute_all(*, target=None, path=None, cfg=None, category=None):
    return [execute(f.id,target=target,path=path,cfg=cfg) for f in FEATURES if category is None or f.category==category]
