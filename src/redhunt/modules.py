from __future__ import annotations

import json, re, socket, ssl, time, urllib.parse, urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict
from .core import RateLimiter, redact


def fetch(url, timeout=10, limiter=None, method="GET"):
    if limiter: limiter.wait()
    req=urllib.request.Request(url,headers={"User-Agent":"Red-Team-Hunting/0.1.0","Accept":"*/*"},method=method)
    started=time.time()
    try:
        with urllib.request.urlopen(req,timeout=timeout) as r:
            return {"status":r.status,"headers":dict(r.headers),"body":r.read(2_000_000).decode("utf-8","replace"),"latency":round(time.time()-started,3),"url":r.geturl()}
    except Exception as exc: return {"status":0,"headers":{},"body":"","latency":round(time.time()-started,3),"error":redact(str(exc)),"url":url}


def tls_audit(host, port=443, timeout=10):
    context=ssl.create_default_context(); started=time.time()
    try:
        with socket.create_connection((host,port),timeout=timeout) as raw:
            with context.wrap_socket(raw,server_hostname=host) as conn:
                cert=conn.getpeercert(); cipher=conn.cipher()
                return {"status":"DETECTED","host":host,"tls_version":conn.version(),"cipher":cipher,"subject":cert.get("subject"),"issuer":cert.get("issuer"),"san":cert.get("subjectAltName"),"latency":round(time.time()-started,3)}
    except Exception as exc: return {"status":"FAILED","host":host,"error":str(exc)}


def robots_and_sitemap(base, timeout=10, limiter=None):
    robots=fetch(base.rstrip("/")+"/robots.txt",timeout,limiter); sitemap=fetch(base.rstrip("/")+"/sitemap.xml",timeout,limiter)
    disallow=re.findall(r"(?im)^\s*disallow:\s*(\S+)",robots.get("body","")); urls=re.findall(r"<loc>\s*(.*?)\s*</loc>",sitemap.get("body",""),re.I)
    return {"robots":{"status":robots["status"],"disallow":disallow[:500]},"sitemap":{"status":sitemap["status"],"urls":urls[:500]}}


def technology(response):
    headers={k.lower():v for k,v in response.get("headers",{}).items()}; body=response.get("body","")
    markers={"server":headers.get("server"),"powered_by":headers.get("x-powered-by"),"wordpress":"wp-content" in body.lower(),"react":"react" in body.lower(),"nextjs":"_next/" in body,"cloudflare":"cloudflare" in headers.get("server","").lower() or "cf-ray" in headers}
    return {"observed":{k:v for k,v in markers.items() if v not in (False,None)},"evidence":{"headers":headers,"body_bytes":len(body)}}


def cookie_audit(response):
    cookies=response.get("headers",{}).get("Set-Cookie","")
    if not cookies: return {"status":"NOT DETECTED","cookies":[]}
    records=[]
    for item in cookies.split(","):
        name=item.split("=",1)[0].strip(); low=item.lower()
        records.append({"name":name,"secure":"secure" in low,"httponly":"httponly" in low,"samesite":"samesite" in low,"evidence":"Set-Cookie attributes observed; value omitted"})
    return {"status":"DETECTED","cookies":records}


def cors_audit(base, timeout=10, limiter=None):
    response=fetch(base,timeout,limiter,"OPTIONS"); headers={k.lower():v for k,v in response.get("headers",{}).items()}; origin=headers.get("access-control-allow-origin")
    return {"status":"DETECTED" if origin else "NOT DETECTED","http_status":response.get("status"),"allow_origin":origin,"evidence":{"headers":headers}}


def port_discovery(host, ports, timeout=1, concurrency=10):
    def probe(port):
        try:
            with socket.create_connection((host,port),timeout=timeout): return {"port":port,"status":"OPEN"}
        except (OSError,TimeoutError): return {"port":port,"status":"CLOSED_OR_FILTERED"}
    with ThreadPoolExecutor(max_workers=max(1,min(concurrency,50))) as pool: return [f.result() for f in as_completed([pool.submit(probe,p) for p in ports])]


def reverse_static_analysis(path):
    from pathlib import Path
    import hashlib, math
    data=Path(path).read_bytes(); counts=[data.count(bytes([i])) for i in range(256)]; total=max(len(data),1)
    entropy=round(-sum((n/total)*math.log2(n/total) for n in counts if n),4)
    text=data.decode("latin1","ignore")
    urls=sorted(set(re.findall(r"https?://[^\\s\\\"'<>]+",text)))[:200]
    ips=sorted(set(re.findall(r"(?<![\\d.])(?:\\d{1,3}\\.){3}\\d{1,3}(?![\\d.])",text)))[:200]
    imports=sorted(set(re.findall(r"(?i)(?:import|loadlibrary|dlopen)[\\s:=]+([A-Za-z0-9_./-]+)",text)))[:200]
    return {"entropy":entropy,"headers":{"magic_hex":data[:16].hex(),"size":len(data)},"embedded_urls":urls,"embedded_ips":ips,"import_indicators":imports,"export_indicators":sorted(set(re.findall(r"(?i)export[s]?[:=]\\s*([A-Za-z0-9_]+)",text)))[:200],"secret_indicators":sorted(set(re.findall(r"(?i)\\b(API_KEY|TOKEN|SECRET|PASSWORD|PRIVATE_KEY)\\b",text))),"hashes":{a:hashlib.new(a,data).hexdigest() for a in ("md5","sha1","sha256","sha512")}}


def ct_subdomains(domain, timeout=10):
    url="https://crt.sh/?q="+urllib.parse.quote("%."+domain,safe="")+"&output=json"
    response=fetch(url,timeout)
    names=set()
    if response.get("status")==200:
        try:
            for row in json.loads(response["body"]): names.update(n.strip().lower() for n in row.get("name_value","").splitlines() if n.strip() and "*" not in n)
        except json.JSONDecodeError: pass
    return {"status":"DETECTED" if names else "NOT DETECTED","source":"crt.sh","domain":domain,"subdomains":sorted(names),"evidence":{"http_status":response.get("status"),"response_bytes":len(response.get("body",""))}}
