from __future__ import annotations

import gzip
import json
import re
import sqlite3
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

NVD_FEED="https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz"
KEV_FEED="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CPE_RE=re.compile(r"^cpe:2\.3:[aho]:([^:]+):([^:]+):([^:]+)")


def _db(path: str|Path) -> sqlite3.Connection:
    path=Path(path).expanduser()
    path.parent.mkdir(parents=True,exist_ok=True)
    db=sqlite3.connect(str(path))
    db.execute("CREATE TABLE IF NOT EXISTS cves (cve_id TEXT PRIMARY KEY, source TEXT NOT NULL, published TEXT, modified TEXT, description TEXT, severity TEXT, cvss_score REAL, cwes TEXT, kev INTEGER NOT NULL DEFAULT 0, vendors TEXT, products TEXT, versions TEXT, refs_json TEXT, cpes TEXT, raw_json TEXT NOT NULL, synced_at REAL NOT NULL)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_cves_products ON cves(products)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_cves_vendors ON cves(vendors)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_cves_kev ON cves(kev)")
    return db


def _get(url: str, timeout: float=60.0) -> bytes:
    req=urllib.request.Request(url,headers={"User-Agent":"RED-TEAM-HUNTING-CVE-Sync/1.0"})
    with urllib.request.urlopen(req,timeout=timeout) as response: return response.read()


def _first_description(item: dict) -> str:
    descriptions=item.get("cve",{}).get("descriptions",[])
    for entry in descriptions:
        if entry.get("lang")=="en": return str(entry.get("value",""))
    return str(descriptions[0].get("value","")) if descriptions else ""


def _extract_cpes(item: dict) -> tuple[list[str],list[str],list[str],list[str]]:
    vendors=set(); products=set(); versions=set(); cpes=set()
    def walk(node):
        if isinstance(node,dict):
            match=node.get("criteria") or node.get("cpe23Uri")
            if match:
                cpes.add(str(match)); parsed=CPE_RE.match(str(match))
                if parsed:
                    vendor,product,version=parsed.groups()
                    vendors.add(urllib.parse.unquote(vendor)); products.add(urllib.parse.unquote(product))
                    if version not in {"*","-"}: versions.add(urllib.parse.unquote(version))
            for value in node.values(): walk(value)
        elif isinstance(node,list):
            for value in node: walk(value)
    walk(item.get("cve",{}).get("configurations",[]))
    return sorted(vendors),sorted(products),sorted(versions),sorted(cpes)


def _cvss(item: dict) -> tuple[str,float|None]:
    metrics=item.get("cve",{}).get("metrics",{})
    for key,severity_key,score_key in (("cvssMetricV40","baseSeverity","baseScore"),("cvssMetricV31","baseSeverity","baseScore"),("cvssMetricV30","baseSeverity","baseScore"),("cvssMetricV2","baseSeverity","baseScore")):
        if metrics.get(key):
            data=metrics[key][0].get("cvssData",metrics[key][0])
            return str(data.get(severity_key) or metrics[key][0].get(severity_key) or "UNKNOWN"), data.get(score_key)
    return "UNKNOWN",None


def _normal(item: dict, kev_ids: set[str]) -> tuple:
    cve=item.get("cve",{})
    metadata=cve.get("cveMetadata",{})
    cve_id=cve.get("id") or metadata.get("cveId")
    vendors,products,versions,cpes=_extract_cpes(item)
    severity,score=_cvss(item)
    refs=[r.get("url") for r in cve.get("references",[]) if r.get("url")]
    weaknesses=[]
    for group in cve.get("weaknesses",[]):
        for desc in group.get("description",[]):
            if desc.get("value"): weaknesses.append(desc["value"])
    return (cve_id,"NVD",cve.get("published"),cve.get("lastModified"),_first_description(item),severity,score,json.dumps(sorted(set(weaknesses))),1 if cve_id in kev_ids else 0,json.dumps(vendors),json.dumps(products),json.dumps(versions),json.dumps(refs),json.dumps(cpes),json.dumps(item,ensure_ascii=False),time.time())


def sync_feed(path: str|Path, year: int, timeout: float=120.0) -> dict:
    raw=_get(NVD_FEED.format(year=year),timeout); payload=json.loads(gzip.decompress(raw).decode("utf-8"))
    kev_ids=set()
    try:
        kev=json.loads(_get(KEV_FEED,timeout).decode("utf-8")); kev_ids={str(x.get("cveID")) for x in kev.get("vulnerabilities",[]) if x.get("cveID")}
    except Exception:
        pass
    db=_db(path); count=0
    try:
        for item in payload.get("vulnerabilities",[]):
            row=_normal(item,kev_ids)
            if row[0]: db.execute("INSERT OR REPLACE INTO cves VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",row); count+=1
        db.commit()
    finally: db.close()
    return {"status":"COMPLETED","source":"NVD JSON 2.0","year":year,"imported":count,"database":str(path),"kev_marked":len(kev_ids)}


def sync_years(path: str|Path, start_year: int=2002, end_year: int|None=None) -> dict:
    end_year=end_year or datetime.now(timezone.utc).year
    results=[]; imported=0
    for year in range(max(2002,start_year),end_year+1):
        try:
            result=sync_feed(path,year); results.append(result); imported+=int(result.get("imported",0))
        except Exception as exc:
            results.append({"status":"INCONCLUSIVE","year":year,"reason":str(exc)})
    return {"status":"COMPLETED" if imported else "INCONCLUSIVE","years":results,"imported":imported,"database":str(path)}


def search(path: str|Path, query: str, limit: int=20, kev_only: bool=False) -> list[dict]:
    db=_db(path); terms=[x.lower() for x in query.split() if x.strip()]; clauses=[]; args=[]
    for term in terms:
        clauses.append("(lower(cve_id) LIKE ? OR lower(description) LIKE ? OR lower(vendors) LIKE ? OR lower(products) LIKE ? OR lower(versions) LIKE ?)"); args.extend([f"%{term}%"]*5)
    if kev_only: clauses.append("kev=1")
    where=" AND ".join(clauses) or "1=1"
    rows=db.execute(f"SELECT cve_id,description,severity,cvss_score,kev,vendors,products,versions,published,modified,refs_json FROM cves WHERE {where} ORDER BY kev DESC,cvss_score DESC,modified DESC LIMIT ?",(*args,max(1,min(int(limit),200)))).fetchall(); db.close()
    keys=("cve_id","description","severity","cvss_score","kev","vendors","products","versions","published","modified","refs_json")
    return [dict(zip(keys,row)) for row in rows]


def correlate(path: str|Path, evidence: dict, limit: int=20) -> dict:
    product=str(evidence.get("product") or evidence.get("technology") or "").strip()
    version=str(evidence.get("version") or "").strip()
    if not product:
        return {"status":"NOT TESTED","reason":"bukti product/technology tidak tersedia; CVE tidak ditebak dari nama host","matches":[]}
    query=product
    matches=search(path,query,limit)
    verified=[]; candidates=[]
    for item in matches:
        products=json.loads(item["products"] or "[]"); versions=json.loads(item["versions"] or "[]")
        product_hit=any(product.lower() in str(x).lower() or str(x).lower() in product.lower() for x in products)
        version_hit=not version or any(version.lower()==str(x).lower() for x in versions)
        if product_hit and version_hit: verified.append({**item,"match_basis":["product" if product_hit else "","version" if version_hit else ""]})
        elif product_hit: candidates.append({**item,"match_basis":["product"],"reason":"versi belum cocok secara eksplisit"})
    if verified: status="DETECTED"
    elif candidates: status="INCONCLUSIVE"
    else: status="NOT DETECTED"
    return {"status":status,"product":product,"version":version,"verified_matches":verified[:limit],"candidate_matches":candidates[:limit],"source":"NVD; penanda eksploitasi CISA KEV bila tersedia"}


def stats(path: str|Path) -> dict:
    db=_db(path); row=db.execute("SELECT COUNT(*),SUM(kev),MAX(modified) FROM cves").fetchone(); db.close()
    return {"status":"COMPLETED" if row[0] else "NOT TESTED","records":row[0],"cisa_kev_records":row[1] or 0,"latest_modified":row[2],"database":str(path)}
