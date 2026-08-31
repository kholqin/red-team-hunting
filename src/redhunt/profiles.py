from __future__ import annotations

PROFILES={
    "passive":{"timeout":10.0,"rate_limit":2.0,"concurrency":2,"crawl_depth":0,"active_testing":False,"recursive":False},
    "safe":{"timeout":10.0,"rate_limit":3.0,"concurrency":3,"crawl_depth":1,"active_testing":False,"recursive":False},
    "standard":{"timeout":12.0,"rate_limit":5.0,"concurrency":5,"crawl_depth":2,"active_testing":True,"recursive":False},
    "aggressive":{"timeout":15.0,"rate_limit":5.0,"concurrency":8,"crawl_depth":3,"active_testing":True,"recursive":True},
    "deep":{"timeout":20.0,"rate_limit":3.0,"concurrency":6,"crawl_depth":5,"active_testing":True,"recursive":True},
}


def apply_profile(cfg: dict, name: str | None) -> dict:
    selected=(name or cfg.get("profile") or "safe").lower()
    if selected not in PROFILES: raise ValueError(f"profile tidak dikenal: {name}")
    merged=dict(cfg); merged.update(PROFILES[selected]); merged["profile"]=selected
    # Aggressive remains non-destructive by policy; callers must not override this.
    merged["safe_mode"]=True
    return merged
