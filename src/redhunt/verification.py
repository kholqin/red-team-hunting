from __future__ import annotations

import hashlib
import json


def response_fingerprint(status: int, headers: dict, body: str) -> str:
    selected={k.lower():str(v) for k,v in headers.items() if k.lower() in {"content-type","location","access-control-allow-origin"}}
    material=json.dumps({"status":status,"headers":selected,"body_length":len(body),"body_hash":hashlib.sha256(body[:200000].encode("utf-8","replace")).hexdigest()},sort_keys=True)
    return hashlib.sha256(material.encode()).hexdigest()


def verify_consistent(observations: list[dict], key: str, required_repeats: int = 2) -> dict:
    values=[item.get(key) for item in observations]
    if len(values)<required_repeats:
        return {"status":"INCONCLUSIVE","reason":"pengulangan evidence belum mencukupi","observations":len(values)}
    if all(value==values[0] for value in values) and values[0] is not None:
        return {"status":"VERIFIED","confidence":min(99,80+10*len(values)),"observations":len(values),"value":values[0]}
    return {"status":"INCONCLUSIVE","reason":"hasil antar-pengulangan tidak konsisten","observations":len(values),"values":values}
