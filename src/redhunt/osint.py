from __future__ import annotations

import json, re, socket, ssl, urllib.parse, urllib.request
from pathlib import Path
from typing import Callable

UA="Red-Team-Hunting/0.1.0"

FEATURES=[
("OS-01","Domain intelligence"),("OS-02","Subdomain intelligence"),("OS-03","WHOIS intelligence"),("OS-04","ASN intelligence"),("OS-05","IP intelligence"),("OS-06","Reverse DNS intelligence"),("OS-07","Certificate intelligence"),("OS-08","Email domain intelligence"),("OS-09","Username enumeration"),("OS-10","Public profile discovery"),("OS-11","GitHub repository intelligence"),("OS-12","GitHub organization intelligence"),("OS-13","Public code search"),("OS-14","Public secret indicator scanning"),("OS-15","Paste-site reference discovery"),("OS-16","Document metadata extraction"),("OS-17","PDF metadata analysis"),("OS-18","Image metadata analysis"),("OS-19","EXIF extraction"),("OS-20","URL intelligence"),("OS-21","Historical URL discovery"),("OS-22","Archived endpoint discovery"),("OS-23","Technology intelligence"),("OS-24","CMS detection"),("OS-25","JavaScript library detection"),("OS-26","WAF detection"),("OS-27","CDN detection"),("OS-28","Cloud provider detection"),("OS-29","Email pattern discovery"),("OS-30","Public contact discovery"),("OS-31","Organization intelligence"),("OS-32","Company domain mapping"),("OS-33","Brand/domain correlation"),("OS-34","Certificate relationship mapping"),("OS-35","IP relationship mapping"),("OS-36","Subdomain relationship graph"),("OS-37","URL relationship graph"),("OS-38","Asset relationship graph"),("OS-39","Public breach-reference detection"),("OS-40","Credential exposure indicator"),("OS-41","Repository secret indicator"),("OS-42","Configuration exposure indicator"),("OS-43","Backup-file indicator"),("OS-44","Debug endpoint discovery"),("OS-45","Public documentation discovery"),("OS-46","Swagger/OpenAPI discovery"),("OS-47","Security.txt discovery"),("OS-48","Robots intelligence"),("OS-49","Sitemap intelligence"),("OS-50","OSINT correlation engine"),
]

def fetch(url,timeout=10):
    req=urllib.request.Request(url,headers={"User-Agent":UA,"Accept":"*/*"})
    try:
        with urllib.request.urlopen(req,timeout=timeout) as r: return {"status":r.status,"url":r.geturl(),"headers":dict(r.headers),"body":r.read(2_000_000).decode("utf-8","replace")}
    except Exception as exc: return {"status":0,"url":url,"headers":{},"body":"","error":str(exc)}

def result(fid,name,status,data,evidence): return {"id":fid,"name":name,"status":status,"data":data,"evidence":evidence}

def domain(ctx):
    host=ctx["host"]
    try: ips=sorted({x[4][0] for x in socket.getaddrinfo(host,None)})
    except OSError as e: return result("OS-01","Domain intelligence","INCONCLUSIVE",{}, {"error":str(e)})
    return result("OS-01","Domain intelligence","DETECTED" if ips else "NOT DETECTED",{"host":host,"ips":ips},{"resolver":"socket.getaddrinfo"})

def subdomain(ctx):
    names=ctx.get("ct",[]); return result("OS-02","Subdomain intelligence","DETECTED" if names else "NOT DETECTED",{"subdomains":names},{"source":"crt.sh response"})

def whois(ctx):
    return result("OS-03","WHOIS intelligence","SKIPPED",{}, {"reason":"WHOIS client/service belum dikonfigurasi; tidak mengarang data."})

def asn(ctx): return result("OS-04","ASN intelligence","SKIPPED",{}, {"reason":"ASN provider tidak dikonfigurasi."})
def ipintel(ctx): return result("OS-05","IP intelligence","DETECTED" if ctx.get("ips") else "NOT DETECTED",{"ips":ctx.get("ips",[])},{"source":"DNS resolution aktual"})
def reverse_dns(ctx):
    rows=[]
    for ip in ctx.get("ips",[]):
        try: rows.append({"ip":ip,"hostname":socket.gethostbyaddr(ip)[0]})
        except OSError: rows.append({"ip":ip,"hostname":None,"status":"NO_PTR"})
    return result("OS-06","Reverse DNS intelligence","DETECTED" if any(x.get("hostname") for x in rows) else "NOT DETECTED",rows,{"source":"PTR lookup aktual"})
def cert(ctx): return result("OS-07","Certificate intelligence","DETECTED" if ctx.get("tls",{}).get("status")=="DETECTED" else "INCONCLUSIVE",ctx.get("tls",{}),{"source":"TLS handshake aktual"})
def emails(ctx):
    found=sorted(set(re.findall(r"[A-Za-z0-9._%+-]+@"+re.escape(ctx["host"]),ctx.get("body",""),re.I)))
    return result("OS-08","Email domain intelligence","DETECTED" if found else "NOT DETECTED",{"emails":found},{"source":"body response aktual","values_redacted":False})
def unavailable(fid,name,reason): return result(fid,name,"SKIPPED",{}, {"reason":reason})
def web_body(ctx): return ctx.get("body","")
def profiles(ctx): return unavailable("OS-10","Public profile discovery","Username/profile input tidak diberikan; tidak melakukan enumeration spekulatif.")
def github_repos(ctx):
    host=ctx["host"]; response=fetch("https://api.github.com/search/repositories?q="+urllib.parse.quote(host),ctx["timeout"])
    if response["status"]!=200: return result("OS-11","GitHub repository intelligence","INCONCLUSIVE",{}, {"url":response["url"],"status":response["status"],"error":response.get("error")})
    try: items=json.loads(response["body"]).get("items",[]); return result("OS-11","GitHub repository intelligence","DETECTED" if items else "NOT DETECTED",{"repositories":[{"full_name":x.get("full_name"),"html_url":x.get("html_url")} for x in items[:30]]},{"source":response["url"]})
    except json.JSONDecodeError: return result("OS-11","GitHub repository intelligence","INCONCLUSIVE",{}, {"error":"JSON invalid"})
def github_org(ctx): return unavailable("OS-12","GitHub organization intelligence","Nama organisasi belum diberikan; collector GitHub memerlukan input eksplisit.")
def code_search(ctx): return unavailable("OS-13","Public code search","Search API/token dan query eksplisit belum diberikan.")
def public_secret(ctx):
    hits=[]
    for n,line in enumerate(web_body(ctx).splitlines(),1):
        if re.search(r"(?i)(api[_-]?key|secret|password|token)\s*[:=]",line): hits.append({"line":n,"evidence":"nama field terdeteksi; nilai tidak disimpan"})
    return result("OS-14","Public secret indicator scanning","DETECTED" if hits else "NOT DETECTED",{"matches":hits[:100]},{"source":"body response aktual","redaction":True})
def paste(ctx): return unavailable("OS-15","Paste-site reference discovery","Tidak mengakses paste site tanpa query dan otorisasi eksplisit.")
def docmeta(ctx): return unavailable("OS-16","Document metadata extraction","Path dokumen lokal tidak diberikan.")
def pdfmeta(ctx): return unavailable("OS-17","PDF metadata analysis","Path PDF lokal tidak diberikan.")
def imagemeta(ctx): return unavailable("OS-18","Image metadata analysis","Path image lokal tidak diberikan.")
def exif(ctx): return unavailable("OS-19","EXIF extraction","Path image lokal tidak diberikan.")
def urlintel(ctx):
    links=sorted(set(re.findall(r"https?://[^\s\"'<>]+",web_body(ctx))))[:500]
    return result("OS-20","URL intelligence","DETECTED" if links else "NOT DETECTED",{"urls":links},{"source":"body response aktual"})
def historical(ctx):
    url="https://web.archive.org/cdx/search/cdx?url="+urllib.parse.quote(ctx["host"]+"/*")+"&output=json&filter=statuscode:200&fl=original,timestamp&collapse=urlkey"
    r=fetch(url,ctx["timeout"])
    if r["status"]!=200: return result("OS-21","Historical URL discovery","INCONCLUSIVE",{}, {"url":url,"status":r["status"],"error":r.get("error")})
    try: rows=json.loads(r["body"]); return result("OS-21","Historical URL discovery","DETECTED" if len(rows)>1 else "NOT DETECTED",{"rows":rows[1:501]},{"source":url})
    except json.JSONDecodeError: return result("OS-21","Historical URL discovery","INCONCLUSIVE",{}, {"error":"JSON invalid"})
def archived(ctx): return historical(ctx)|{"id":"OS-22","name":"Archived endpoint discovery"}
def tech(ctx): return result("OS-23","Technology intelligence", "DETECTED" if ctx.get("technology") else "NOT DETECTED",ctx.get("technology",{}),{"source":"headers/body response aktual"})
def cms(ctx): return result("OS-24","CMS detection","DETECTED" if any(x in web_body(ctx).lower() for x in ["wp-content","drupalSettings","joomla"]) else "NOT DETECTED",{}, {"source":"body marker aktual"})
def js(ctx):
    scripts=re.findall(r"<script[^>]+src=[\"']([^\"']+)",web_body(ctx),re.I); return result("OS-25","JavaScript library detection","DETECTED" if scripts else "NOT DETECTED",{"scripts":scripts[:200]},{"source":"HTML aktual"})
def waf(ctx):
    h={k.lower():v for k,v in ctx.get("headers",{}).items()}; marks=[k for k in ["cf-ray","x-sucuri-id","x-cdn","x-waf"] if k in h]; return result("OS-26","WAF detection","DETECTED" if marks else "NOT DETECTED",{"headers":marks},{"source":"response headers aktual"})
def cdn(ctx): return waf(ctx)|{"id":"OS-27","name":"CDN detection"}
def cloud(ctx): return result("OS-28","Cloud provider detection","DETECTED" if ctx.get("cloud",{}).get("providers") else "NOT DETECTED",ctx.get("cloud",{}),{"source":"response aktual"})
def emailpattern(ctx): return emails(ctx)|{"id":"OS-29","name":"Email pattern discovery"}
def contact(ctx): return emails(ctx)|{"id":"OS-30","name":"Public contact discovery"}
def unavailable_asset(fid,name): return unavailable(fid,name,"Input organisasi/brand/repository eksplisit belum diberikan.")
def graph(ctx): return result("OS-36","Subdomain relationship graph","DETECTED" if ctx.get("ct") else "NOT DETECTED",{"nodes":[ctx["host"]]+ctx.get("ct",[]),"edges":[{"from":ctx["host"],"to":x,"type":"subdomain"} for x in ctx.get("ct",[])]},{"source":"DNS/CT evidence aktual"})
def osint_run(target, timeout=10, context=None):
    p=urllib.parse.urlparse(target); ctx={"target":target,"host":p.hostname,"timeout":timeout}; ctx.update(context or {})
    handlers={"OS-01":domain,"OS-02":subdomain,"OS-03":whois,"OS-04":asn,"OS-05":ipintel,"OS-06":reverse_dns,"OS-07":cert,"OS-08":emails,"OS-09":lambda c: unavailable("OS-09","Username enumeration","Username input eksplisit belum diberikan."),"OS-10":profiles,"OS-11":github_repos,"OS-12":github_org,"OS-13":code_search,"OS-14":public_secret,"OS-15":paste,"OS-16":docmeta,"OS-17":pdfmeta,"OS-18":imagemeta,"OS-19":exif,"OS-20":urlintel,"OS-21":historical,"OS-22":archived,"OS-23":tech,"OS-24":cms,"OS-25":js,"OS-26":waf,"OS-27":cdn,"OS-28":cloud,"OS-29":emailpattern,"OS-30":contact,"OS-31":lambda c: unavailable_asset("OS-31","Organization intelligence"),"OS-32":lambda c: unavailable_asset("OS-32","Company domain mapping"),"OS-33":lambda c: unavailable_asset("OS-33","Brand/domain correlation"),"OS-34":lambda c: unavailable_asset("OS-34","Certificate relationship mapping"),"OS-35":lambda c: result("OS-35","IP relationship mapping","DETECTED" if c.get("ips") else "NOT DETECTED",{"ips":c.get("ips",[])},{"source":"DNS evidence aktual"}),"OS-36":graph,"OS-37":lambda c: result("OS-37","URL relationship graph","DETECTED" if c.get("body") else "NOT DETECTED",{"urls":sorted(set(re.findall(r"https?://[^\\s\"'<>]+",c.get("body",""))))[:200]},{"source":"body aktual"}),"OS-38":lambda c: result("OS-38","Asset relationship graph","DETECTED" if c.get("ips") else "NOT DETECTED",{"domain":c["host"],"ips":c.get("ips",[]),"subdomains":c.get("ct",[])},{"source":"DNS/CT evidence aktual"}),"OS-39":lambda c: unavailable("OS-39","Public breach-reference detection","Breach provider/API key tidak dikonfigurasi; tidak mengambil credential."),"OS-40":lambda c: unavailable("OS-40","Credential exposure indicator","Tidak melakukan pengambilan credential atau breach data."),"OS-41":public_secret,"OS-42":public_secret,"OS-43":lambda c: unavailable("OS-43","Backup-file indicator","Tidak melakukan brute-force path; gunakan input path eksplisit."),"OS-44":lambda c: result("OS-44","Debug endpoint discovery","NOT TESTED",{}, {"reason":"Memerlukan endpoint input eksplisit; tidak menebak path pada target."}),"OS-45":lambda c: result("OS-45","Public documentation discovery","DETECTED" if any(x in c.get("body","").lower() for x in ["documentation","developer","api docs"]) else "NOT DETECTED",{}, {"source":"body aktual"}),"OS-46":lambda c: result("OS-46","Swagger/OpenAPI discovery","DETECTED" if c.get("api") else "NOT DETECTED",c.get("api",{}),{"source":"API probes aktual"}),"OS-47":lambda c: result("OS-47","Security.txt discovery","DETECTED" if c.get("security_txt") else "NOT DETECTED",c.get("security_txt",{}),{"source":"security.txt response aktual"}),"OS-48":lambda c: result("OS-48","Robots intelligence","DETECTED" if c.get("robots") else "NOT DETECTED",c.get("robots",{}),{"source":"robots.txt response aktual"}),"OS-49":lambda c: result("OS-49","Sitemap intelligence","DETECTED" if c.get("sitemap") else "NOT DETECTED",c.get("sitemap",{}),{"source":"sitemap.xml response aktual"}),"OS-50":lambda c: result("OS-50","OSINT correlation engine","DETECTED" if c.get("ips") or c.get("ct") else "NOT DETECTED",{"domain":c["host"],"ips":c.get("ips",[]),"subdomains":c.get("ct",[]),"technology":c.get("technology",{})},{"source":"gabungan evidence collector aktual"})}
    normalized=[]
    for fid,name in FEATURES:
        item=handlers[fid](ctx); item["id"]=fid; item["name"]=name; normalized.append(item)
    return normalized
