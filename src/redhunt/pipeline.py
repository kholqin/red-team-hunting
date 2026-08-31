from __future__ import annotations

import concurrent.futures as futures
import ipaddress
from pathlib import Path
from urllib.parse import urlparse

from .catalog import FEATURES
from .dispatch import execute


def target_kind(value: str) -> str:
    path=Path(value)
    if path.is_file(): return "FILE"
    raw=value if "://" in value else "https://"+value
    parsed=urlparse(raw)
    if parsed.scheme in {"http","https"} and parsed.hostname:
        try: ipaddress.ip_address(parsed.hostname); return "IP_URL"
        except ValueError: return "URL" if parsed.path not in {"","/"} else "DOMAIN_URL"
    try: ipaddress.ip_network(value,strict=False); return "CIDR"
    except ValueError: return "DOMAIN"


def _unsupported(feature, kind, reason):
    return {"id":feature.id,"name":feature.name,"category":feature.category,"status":"SKIPPED","data":{},"evidence":{"target_kind":kind,"reason":reason,"executor":feature.executor}}


def run(target: str, cfg: dict | None = None, *, workers: int = 3) -> dict:
    cfg=cfg or {"timeout":10.0,"retries":1,"concurrency":3,"safe_mode":True}
    kind=target_kind(target)
    if kind=="FILE":
        selected=[f for f in FEATURES if f.category=="REVERSE"]
        with futures.ThreadPoolExecutor(max_workers=max(1,min(workers,4))) as pool:
            results=list(pool.map(lambda f: execute(f.id,path=target,cfg=cfg),selected))
    elif kind in {"DOMAIN","DOMAIN_URL","URL","IP_URL"}:
        selected=[f for f in FEATURES if f.category in {"BUG_BOUNTY","OSINT"}]
        # Aggregators are used once per category to avoid duplicate network requests.
        from .bugbounty import run_bug_bounty
        from .osint import osint_run
        bounty=run_bug_bounty(target,cfg)
        osint=osint_run(target,cfg.get("timeout",10),{})
        by_id={item.get("id"):item for item in bounty+osint}
        results=[]
        for feature in selected:
            item=by_id.get(feature.id)
            results.append({**item,"category":feature.category,"executor":feature.executor} if item else _unsupported(feature,kind,"aggregator tidak mengembalikan record"))
    else:
        results=[_unsupported(f,kind,"target type memerlukan adapter khusus") for f in FEATURES]
    return {"target":target,"target_kind":kind,"profile":cfg.get("profile","safe"),"status":"COMPLETED","engine":"target-aware-pipeline","results":results}
