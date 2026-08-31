from __future__ import annotations

import argparse, csv, hashlib, json, os, re, shutil, socket, ssl, sqlite3, sys, time, urllib.error, urllib.parse, urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from .bugbounty import run_bug_bounty
from .catalog import catalog, counts
from .dispatch import execute
from .core import PluginLoader
from .language import analyze_path
from .osint import osint_run
from .ui import banner as neon_banner, menu as neon_menu
from .modules import api_document_analysis, cloud_fingerprint, cookie_audit, cors_audit, ct_subdomains, jwt_analyze, passive_osint, port_discovery, reverse_static_analysis, robots_and_sitemap, safe_web_indicators, technology, tls_audit

NAME = "RED TEAM HUNTING"
BRAND = "M4zk1pL4y Scurity"
UA = "Red-Team-Hunting/0.1.0"

@dataclass
class Finding:
    id: str
    name: str
    severity: str
    confidence: int
    target: str
    endpoint: str
    parameter: str
    method: str
    evidence: str
    impact: str
    remediation: str
    timestamp: str

class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True); self.path = path
        with sqlite3.connect(path) as db:
            db.execute("CREATE TABLE IF NOT EXISTS scans (id TEXT PRIMARY KEY, target TEXT, mode TEXT, status TEXT, started REAL, ended REAL, result TEXT)")
            for table in ("projects","targets","domains","subdomains","ips","ports","services","technologies","endpoints","parameters","findings","evidence","osint_results","reverse_results","scan_jobs","logs"):
                db.execute(f"CREATE TABLE IF NOT EXISTS {table} (id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT, target TEXT, data TEXT, created REAL)")
    def save(self, scan_id: str, target: str, mode: str, status: str, result: dict):
        with sqlite3.connect(self.path) as db:
            db.execute("INSERT OR REPLACE INTO scans VALUES (?,?,?,?,?,?,?)", (scan_id,target,mode,status,result.get("started",0),time.time(),json.dumps(result)))
    def list(self):
        with sqlite3.connect(self.path) as db: return db.execute("SELECT id,target,mode,status FROM scans ORDER BY started DESC").fetchall()
    def get(self, scan_id):
        with sqlite3.connect(self.path) as db:
            row=db.execute("SELECT result FROM scans WHERE id=?",(scan_id,)).fetchone()
        return json.loads(row[0]) if row else None

def say(level: str, message: str): print(f"[{level}] {message}")
def banner():
    print("╔══════════════════════════════════════════════════════════════════╗")
    print("║                    RED TEAM HUNTING                              ║")
    print(f"║                    {BRAND:<44}║")
    print("║              BUG BOUNTY & SECURITY RESEARCH                      ║")
    print("╚══════════════════════════════════════════════════════════════════╝")

def config_dir(): return Path(os.environ.get("REDHUNT_HOME", Path.home()/".redhunt"))
def load_config():
    cfg={"safe_mode":True,"scope_enforcement":True,"timeout":10.0,"rate_limit":5.0,"concurrency":10}
    p=config_dir()/"config.json"
    if p.exists():
        try: cfg.update(json.loads(p.read_text(encoding="utf-8")))
        except (OSError,ValueError): say("PERINGATAN","Konfigurasi tidak valid; menggunakan default.")
    return cfg

def normalize_target(value: str) -> str:
    value=value.strip()
    if not value: raise ValueError("Target kosong.")
    if "://" not in value: value="https://"+value
    u=urllib.parse.urlparse(value)
    if u.scheme not in {"http","https"} or not u.hostname: raise ValueError("Target harus berupa domain, IP, hostname, atau URL HTTP(S) yang valid.")
    if any(c in value for c in "\r\n\x00") or any(ch.isspace() for ch in value): raise ValueError("Target mengandung karakter terlarang.")
    return value.rstrip("/")

def in_scope(target: str, cfg: dict) -> bool:
    if not cfg.get("scope_enforcement",True): return True
    scope_file=Path("scope.json")
    if not scope_file.exists():
        yaml_file=Path("scope.yaml")
        if not yaml_file.exists(): return True
        rules={"allowed":[],"excluded":[]}; section=None
        for line in yaml_file.read_text(encoding="utf-8").splitlines():
            stripped=line.strip()
            if stripped in {"allowed:","excluded:"}: section=stripped[:-1]
            elif section and stripped.startswith("-"): rules[section].append(stripped[1:].strip().strip("\"'"))
    else:
        try: rules=json.loads(scope_file.read_text(encoding="utf-8"))
        except Exception: return False
    host=(urllib.parse.urlparse(target).hostname or "").lower().rstrip(".")
    allowed=rules.get("allowed",[]); excluded=rules.get("excluded",[])
    match=lambda pat: host==pat.lower().lstrip("*.") or (pat.startswith("*.") and host.endswith(pat[1:].lower()))
    return bool(allowed and any(match(x) for x in allowed) and not any(match(x) for x in excluded))

def sanitize_headers(headers):
    clean={}
    for key,value in headers.items():
        low=key.lower()
        if low in {"authorization","proxy-authorization","x-api-key"} or "token" in low or "password" in low:
            clean[key]="[REDACTED]"
        elif low=="set-cookie":
            clean[key]=re.sub(r"(=[^;]*)", "=[REDACTED]", value, count=1)
        else: clean[key]=value
    return clean

def request(url: str, cfg: dict, method="GET") -> tuple[int,dict,str,float]:
    started=time.time(); attempts=max(1,min(int(cfg.get("retries",2))+1,4)); delay=0.0
    for attempt in range(attempts):
        if delay: time.sleep(delay)
        req=urllib.request.Request(url,headers={"User-Agent":UA,"Accept":"*/*"},method=method)
        try:
            with urllib.request.urlopen(req,timeout=float(cfg["timeout"])) as r:
                body=r.read(1_000_000).decode("utf-8","replace"); return r.status,sanitize_headers(dict(r.headers)),body,time.time()-started
        except urllib.error.HTTPError as e:
            body=e.read(1_000_000).decode("utf-8","replace")
            if e.code not in {408,425,429,500,502,503,504} or attempt==attempts-1: return e.code,sanitize_headers(dict(e.headers)),body,time.time()-started
        except Exception as e:
            if attempt==attempts-1: return 0,{"error":str(e),"attempts":attempts},"",time.time()-started
        delay=0.25*(2**attempt)
    return 0,{"error":"request gagal tanpa respons","attempts":attempts},"",time.time()-started

def dns(target: str):
    host=urllib.parse.urlparse(normalize_target(target)).hostname
    out=[]
    try:
        for item in socket.getaddrinfo(host,None):
            ip=item[4][0]
            if ip not in out: out.append(ip)
    except socket.gaierror as e: return {"host":host,"ips":[],"error":str(e)}
    return {"host":host,"ips":out}

def headers(target,cfg):
    status,h,b,lat=request(target,cfg,"GET")
    required=["content-security-policy","strict-transport-security","x-frame-options","x-content-type-options","referrer-policy","permissions-policy"]
    missing=[x for x in required if x not in {k.lower() for k in h}]
    return {"url":target,"status":status,"latency":round(lat,3),"headers":h,"missing_security_headers":missing,"body_length":len(b)}

def endpoints(target,cfg):
    status,h,body,_=request(target,cfg)
    paths=sorted(set(re.findall(r"(?:href|src|action)=[\"']([^\"'#? ]+)",body,re.I)))
    paths += sorted(set(re.findall(r"(?:/api/|/graphql|/swagger(?:\.json)?|/openapi(?:\.json)?|/robots\.txt|/sitemap\.xml)[A-Za-z0-9_./?=&-]*",body,re.I)))
    return {"status":status,"endpoints":sorted(set(paths))[:500],"source":"HTML response"}

def api_check(target,cfg):
    base=target.rstrip("/"); found=[]
    for path in ("/openapi.json","/swagger.json","/api-docs","/graphql"):
        s,h,b,l=request(base+path,cfg)
        if s and s not in (404,410): found.append({"path":path,"status":s,"content_type":h.get("Content-Type",""),"bytes":len(b)})
    return {"candidates":found,"tested_paths":4}

def vuln_check(target,cfg):
    result={"checks":[],"findings":[],"status":"INCONCLUSIVE"}; s,h,b,lat=request(target,cfg)
    if not s:
        result["checks"].append({"name":"http_request","status":"FAILED","evidence":h.get("error","request failed")})
        return result
    header_names={k.lower():v for k,v in h.items()}
    required=["content-security-policy","strict-transport-security","x-frame-options","x-content-type-options","referrer-policy","permissions-policy"]
    missing=[name for name in required if name not in header_names]
    result["checks"].append({"name":"security_headers","status":"DETECTED" if missing else "NOT DETECTED","http_status":s,"latency":round(lat,3),"missing":missing,"evidence":{"response_headers":h}})
    finding_id=1
    for name in missing:
        severity="LOW" if name != "strict-transport-security" or not target.lower().startswith("https://") else "MEDIUM"
        result["findings"].append(asdict(Finding(f"RT-{finding_id:03d}",f"Security header tidak ada: {name}",severity,95,target,"/","","GET",f"Header {name} tidak ditemukan pada respons HTTP status {s}.","Kontrol keamanan browser yang terkait belum terlihat pada respons ini.",f"Tinjau dan tambahkan header {name} sesuai kebutuhan aplikasi.",time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()))))
        finding_id += 1
    acao=header_names.get("access-control-allow-origin")
    if acao == "*":
        result["findings"].append(asdict(Finding(f"RT-{finding_id:03d}","CORS wildcard","MEDIUM",95,target,"/","","GET","Respons aktual memuat Access-Control-Allow-Origin: *.","Origin mana pun dapat diizinkan oleh kebijakan CORS; dampak bergantung pada jenis data dan kredensial.","Batasi origin ke daftar origin tepercaya dan tinjau penggunaan kredensial CORS.",time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()))))
    result["status"]="DETECTED" if result["findings"] else "NOT DETECTED"
    return result

def reverse(path: str):
    p=Path(path)
    if not p.is_file(): raise ValueError("File reverse tidak ditemukan.")
    data=p.read_bytes(); magic=data[:16]
    kind="unknown"
    if data.startswith(b"\x7fELF"): kind="ELF"
    elif data[:2]==b"MZ": kind="PE"
    elif data.startswith(b"PK\x03\x04"): kind="ZIP/APK/JAR"
    elif data[:4] in (b"\xfe\xed\xfa\xce",b"\xce\xfa\xed\xfe",b"\xfe\xed\xfa\xcf",b"\xcf\xfa\xed\xfe"): kind="Mach-O"
    strings=sorted(set(x.decode("ascii","ignore") for x in re.findall(rb"[ -~]{6,}",data)))[:200]
    indicators=[]
    for pat in (b"API_KEY",b"TOKEN",b"SECRET",b"PASSWORD",b"PRIVATE_KEY"):
        if pat in data: indicators.append(pat.decode())
    return {"file":str(p),"type":kind,"size":len(data),"hashes":{a:hashlib.new(a,data).hexdigest() for a in ("md5","sha1","sha256","sha512")},"entropy_hint":round(len(set(data))/256,3),"strings":strings,"secret_indicators":indicators}

def overall_status(data):
    encoded=json.dumps(data,ensure_ascii=False)
    if '"status": "FAILED"' in encoded or '"status": "INCONCLUSIVE"' in encoded: return "INCONCLUSIVE"
    return "COMPLETED"

def output(data: Any, fmt: str, path: str|None):
    if fmt=="table":
        rows=data if isinstance(data,list) else [{"field":k,"value":v} for k,v in data.items()]
        print("FIELD | VALUE")
        for row in rows:
            if isinstance(row,dict):
                if "field" in row: print(f"{row['field']} | {str(row['value'])[:240]}")
                else: print(" | ".join(f"{k}: {str(v)[:120]}" for k,v in row.items()))
        return
    if fmt=="json": text=json.dumps(data,ensure_ascii=False,indent=2)
    elif fmt=="csv":
        rows=data if isinstance(data,list) else [data]; keys=sorted({k for r in rows if isinstance(r,dict) for k in r}); import io; buf=io.StringIO(); w=csv.DictWriter(buf,fieldnames=keys); w.writeheader(); w.writerows(rows); text=buf.getvalue()
    elif fmt in {"md","txt","html"}: text=("# Red Team Hunting Report\n\n"+json.dumps(data,ensure_ascii=False,indent=2)) if fmt=="md" else json.dumps(data,ensure_ascii=False,indent=2)
    else: text=json.dumps(data,ensure_ascii=False,indent=2)
    if path: Path(path).write_text(text,encoding="utf-8"); say("SELESAI",f"Laporan tersimpan: {path}")
    else: print(text)

def doctor():
    checks=[]
    for name,cmd in [("Python",sys.executable),("pip","pip"),("git","git"),("curl","curl"),("openssl","openssl"),("nmap","nmap"),("ffuf","ffuf"),("nuclei","nuclei"),("gobuster","gobuster"),("amass","amass"),("subfinder","subfinder"),("apktool","apktool"),("jadx","jadx"),("radare2","radare2")]: checks.append({"dependency":name,"status":"TERSEDIA" if shutil.which(cmd) else ("OPSIONAL TIDAK TERSEDIA" if name not in {"Python"} else "GAGAL")})
    for r in checks: print(f"{r['dependency']:<12} | {r['status']}")
    if os.environ.get("TERMUX_VERSION"): say("INFORMASI","Lingkungan Termux terdeteksi; mode kompatibilitas Android digunakan.")

def main(argv=None):
    ap=argparse.ArgumentParser(prog="redhunt",description="Security toolkit non-destruktif untuk target berizin.")
    ap.add_argument("command",nargs="?",choices=["recon","subdomain","web","api","vuln","osint","bugbounty","reverse","full","doctor","report","plugins","interactive","scan","tls","ports","jwt","source","features","feature"],default="doctor")
    ap.add_argument("target",nargs="?"); ap.add_argument("--path"); ap.add_argument("--token"); ap.add_argument("--input"); ap.add_argument("--output",choices=["table","json","csv","txt","html","md"],default="table"); ap.add_argument("--out"); ap.add_argument("--wordlist"); ap.add_argument("--ports",default="22,80,443,8080,8443"); ap.add_argument("--debug",action="store_true")
    args=ap.parse_args(argv); cfg=load_config(); banner() if args.command in {"interactive","full"} else None
    if args.command=="doctor": doctor(); return 0
    if args.command=="jwt": output(jwt_analyze(args.token or args.target or ""),args.output,args.out); return 0
    if args.command=="bugbounty":
        try:
            target=normalize_target(args.target or "")
            if not in_scope(target,cfg): say("GAGAL","Target ditolak oleh scope enforcement."); return 3
            data={"target":target,"modules":run_bug_bounty(target,cfg)}; output(data,args.output,args.out); return 0
        except ValueError as e: say("GAGAL",str(e)); return 2
    if args.command=="source":
        source=args.path or args.target
        if not source: say("GAGAL","Gunakan redhunt source --path FILE_ATAU_DIREKTORI."); return 2
        output({"status":"COMPLETED","path":source,"results":analyze_path(source)},args.output,args.out); return 0
    if args.command=="feature":
        feature_id=args.target
        if not feature_id: say("GAGAL","Gunakan redhunt feature FEATURE_ID --target URL atau --path FILE."); return 2
        try:
            target=args.input if args.input else None
            data=execute(feature_id,target=target,path=args.path,cfg=cfg)
            output(data,args.output,args.out); return 0
        except ValueError as e: say("GAGAL",str(e)); return 2
    if args.command=="features":
        category=args.target.upper() if args.target and args.target.upper() in {"BUG_BOUNTY","OSINT","REVERSE"} else None
        output({"status":"CATALOG","counts":counts(),"features":catalog(category)},args.output,args.out); return 0
    if args.command=="plugins":
        loader=PluginLoader(); discovered=loader.discover(); print("PLUGIN | STATUS | PATH")
        for meta in discovered: print(f"{meta.parent.name} | METADATA TERSEDIA | {meta.parent}")
        if not discovered: say("INFO","Belum ada plugin dengan plugin.yaml di direktori plugins.")
        return 0
    if args.command=="interactive":
        try:
            neon_banner(); neon_menu()
            chosen=input("Masukkan target berizin untuk full scan: ").strip(); target=normalize_target(chosen)
            if not in_scope(target,cfg): say("GAGAL","Target ditolak oleh scope enforcement."); return 3
            host=urllib.parse.urlparse(target).hostname; data={"target":target,"recon":{"dns":dns(target),"certificate_transparency":ct_subdomains(host,cfg["timeout"]),"tls":tls_audit(host,timeout=cfg["timeout"])},"web":headers(target,cfg),"api":api_check(target,cfg),"vulnerability":vuln_check(target,cfg),"status":"COMPLETED"}; output(data,args.output,args.out); return 0
        except (EOFError,KeyboardInterrupt,ValueError) as e: say("GAGAL",f"Interactive gagal: {e}"); return 2
    if args.command=="scan":
        store=Store(config_dir()/"redhunt.db")
        if args.target=="list":
            rows=store.list(); print("SCAN ID | TARGET | MODE | STATUS"); [print(f"{r[0]} | {r[1]} | {r[2]} | {r[3]}") for r in rows]; return 0
        say("INFO","Gunakan 'redhunt scan list' untuk melihat scan yang tersimpan."); return 0
    if args.command=="report":
        try:
            source=Path(args.input or args.target or "")
            if not source.is_file(): raise ValueError("File hasil scan tidak ditemukan; gunakan --input FILE.")
            output(json.loads(source.read_text(encoding="utf-8")),args.output,args.out); return 0
        except (ValueError, json.JSONDecodeError, OSError) as e: say("GAGAL",f"Report gagal: {e}"); return 2
    if args.command=="reverse":
        try:
            path=args.target or ""; output(reverse(path)|{"static_analysis":reverse_static_analysis(path)},args.output,args.out); return 0
        except ValueError as e: say("GAGAL",str(e)); return 2
    if args.command in {"ports","tls"}:
        try:
            target=normalize_target(args.target or ""); host=urllib.parse.urlparse(target).hostname
            if args.command=="tls": data=tls_audit(host,timeout=cfg["timeout"])
            else: data={"host":host,"results":port_discovery(host,[int(x.strip()) for x in args.ports.split(",") if x.strip()],cfg["timeout"],cfg["concurrency"])}
            output(data,args.output,args.out); return 0
        except (ValueError,OSError) as e: say("GAGAL",f"Pemeriksaan {args.command} gagal: {e}"); return 2
    try: target=normalize_target(args.target or "")
    except ValueError as e: say("GAGAL",str(e)); return 2
    if not in_scope(target,cfg): say("GAGAL","Target ditolak oleh scope enforcement. Periksa scope.json."); return 3
    if args.command in {"recon","subdomain"}:
        host=urllib.parse.urlparse(target).hostname; response=request(target,cfg); data={"target":target,"dns":dns(target),"certificate_transparency":ct_subdomains(host,cfg["timeout"]),"tls":tls_audit(host,timeout=cfg["timeout"]),"endpoints":endpoints(target,cfg),"robots_sitemap":robots_and_sitemap(target,cfg["timeout"])}
        if args.command=="subdomain" and args.wordlist:
            word_path=Path(args.wordlist)
            if not word_path.is_file(): say("PERINGATAN","Wordlist tidak ditemukan; enumerasi wordlist dilewati.")
            else:
                candidates=[x.strip().lower() for x in word_path.read_text(encoding="utf-8",errors="ignore").splitlines() if x.strip()][:10000]; resolved=[]
                for label in candidates:
                    fqdn=f"{label}.{host}"
                    try:
                        ips=sorted({x[4][0] for x in socket.getaddrinfo(fqdn,None)})
                        if ips: resolved.append({"subdomain":fqdn,"ips":ips,"status":"RESOLVED","source":"wordlist DNS"})
                    except socket.gaierror: continue
                data["wordlist_subdomains"]={"tested":len(candidates),"resolved":resolved}
    elif args.command=="osint":
        host=urllib.parse.urlparse(target).hostname; response=request(target,cfg); response_http={"status":response[0],"headers":response[1],"body":response[2]}; ct=ct_subdomains(host,cfg["timeout"]); dns_data=dns(target); tech_data=technology(response_http); cloud_data=cloud_fingerprint(response_http); rs=robots_and_sitemap(target,cfg["timeout"]); data={"target":target,"modules":osint_run(target,cfg["timeout"],{"body":response[2],"headers":response[1],"ips":dns_data.get("ips",[]),"ct":ct.get("subdomains",[]),"tls":tls_audit(host,timeout=cfg["timeout"]),"technology":tech_data,"cloud":cloud_data,"robots":rs.get("robots"),"sitemap":rs.get("sitemap"),"api":api_check(target,cfg),"security_txt":passive_osint(target,cfg["timeout"]).get("security_txt",{})})}
    elif args.command=="web":
        response=request(target,cfg); data=headers(target,cfg)|{"technology":technology(response),"cookies":cookie_audit(response),"robots_sitemap":robots_and_sitemap(target,cfg["timeout"]),"endpoints":endpoints(target,cfg)}
    elif args.command=="api": data=api_check(target,cfg)|{"document_analysis":api_document_analysis(target,cfg["timeout"]),"cors":cors_audit(target,cfg["timeout"])}
    elif args.command=="vuln": data=vuln_check(target,cfg)|{"cors":cors_audit(target,cfg["timeout"]),"safe_web_indicators":safe_web_indicators(target,cfg["timeout"])}
    elif args.command=="full":
        host=urllib.parse.urlparse(target).hostname; response=request(target,cfg); data={"target":target,"recon":{"dns":dns(target),"certificate_transparency":ct_subdomains(host,cfg["timeout"]),"tls":tls_audit(host,timeout=cfg["timeout"])},"web":headers(target,cfg)|{"technology":technology(response),"cookies":cookie_audit(response),"robots_sitemap":robots_and_sitemap(target,cfg["timeout"]),"endpoints":endpoints(target,cfg)},"api":api_check(target,cfg)|{"document_analysis":api_document_analysis(target,cfg["timeout"]),"cors":cors_audit(target,cfg["timeout"])},"cloud":cloud_fingerprint(response),"passive_osint":passive_osint(target,cfg["timeout"]),"vulnerability":vuln_check(target,cfg)|{"safe_web_indicators":safe_web_indicators(target,cfg["timeout"])},"started":time.time()}
    else: data={"error":"Perintah tidak dikenal."}
    status=overall_status(data); output(data,args.output,args.out); Store(config_dir()/"redhunt.db").save(time.strftime("RT-%Y%m%d-%H%M%S"),target,args.command,status,data); return 0

if __name__=="__main__": raise SystemExit(main())
