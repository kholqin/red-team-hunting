from __future__ import annotations

import csv, hashlib, html, json, re, shutil, sqlite3, subprocess, time
from dataclasses import dataclass, asdict
from pathlib import Path
from threading import Lock
import importlib.util
from typing import Any, Iterable
from urllib.parse import urlparse

@dataclass(frozen=True)
class Target:
    raw: str
    normalized: str
    kind: str
    host: str | None = None
    path: str | None = None

class TargetError(ValueError): pass

def parse_target(value: str) -> Target:
    raw=value.strip()
    if not raw or any(c in raw for c in "\r\n\x00") or any(c.isspace() for c in raw):
        raise TargetError("Target kosong atau mengandung karakter terlarang.")
    if "://" not in raw:
        raw="https://"+raw
    parsed=urlparse(raw)
    if parsed.scheme not in {"http","https"} or not parsed.hostname:
        raise TargetError("Target harus berupa URL HTTP(S), domain, hostname, atau IP yang valid.")
    return Target(value,raw.rstrip("/"),"url",parsed.hostname.lower(),parsed.path or "/")

class Scope:
    def __init__(self, allowed: Iterable[str], excluded: Iterable[str], enforcement=True):
        self.allowed=list(allowed); self.excluded=list(excluded); self.enforcement=enforcement
    @classmethod
    def from_file(cls,path=Path("scope.json"), enforcement=True):
        if not Path(path).exists(): return cls([],[],False if enforcement else enforcement)
        data=json.loads(Path(path).read_text(encoding="utf-8")); return cls(data.get("allowed",[]),data.get("excluded",[]),enforcement)
    @staticmethod
    def _matches(host, pattern):
        pattern=pattern.lower().rstrip(".")
        return host==pattern or (pattern.startswith("*.") and host.endswith(pattern[1:]))
    def check(self,target: Target) -> tuple[bool,str]:
        if not self.enforcement: return True,"enforcement disabled"
        if not self.allowed: return True,"no scope file configured"
        if any(self._matches(target.host or "",x) for x in self.excluded): return False,"target berada di daftar excluded"
        if any(self._matches(target.host or "",x) for x in self.allowed): return True,"allowed rule cocok"
        return False,"tidak ada allowed rule yang cocok"

class RateLimiter:
    def __init__(self, requests_per_second=5.0): self.interval=1/max(float(requests_per_second),0.1); self.last=0.0; self.lock=Lock()
    def wait(self):
        with self.lock:
            delay=self.interval-(time.monotonic()-self.last)
            if delay>0: time.sleep(delay)
            self.last=time.monotonic()

class SQLiteStore:
    def __init__(self,path: Path):
        self.path=Path(path); self.path.parent.mkdir(parents=True,exist_ok=True)
        with sqlite3.connect(self.path) as db:
            db.execute("CREATE TABLE IF NOT EXISTS scans (id TEXT PRIMARY KEY,target TEXT,mode TEXT,status TEXT,started REAL,ended REAL,result TEXT)")
            db.execute("CREATE TABLE IF NOT EXISTS findings (id TEXT PRIMARY KEY,scan_id TEXT,target TEXT,severity TEXT,evidence TEXT,created REAL)")
    def save_scan(self,scan_id,target,mode,status,result):
        with sqlite3.connect(self.path) as db: db.execute("INSERT OR REPLACE INTO scans VALUES (?,?,?,?,?,?,?)",(scan_id,target,mode,status,result.get("started",time.time()),time.time(),json.dumps(result,ensure_ascii=False)))
    def save_findings(self,scan_id,findings):
        with sqlite3.connect(self.path) as db:
            for f in findings: db.execute("INSERT OR REPLACE INTO findings VALUES (?,?,?,?,?,?)",(f.get("id"),scan_id,f.get("target"),f.get("severity"),json.dumps(f.get("evidence"),ensure_ascii=False),time.time()))

class ReportWriter:
    @staticmethod
    def render(data: Any, fmt: str) -> str:
        if fmt=="json": return json.dumps(data,ensure_ascii=False,indent=2)
        if fmt=="csv":
            rows=data if isinstance(data,list) else [data]; keys=sorted({k for r in rows if isinstance(r,dict) for k in r}); out=[]; out.append(",".join(keys)); out.extend(",".join(json.dumps(r.get(k,""),ensure_ascii=False) for k in keys) for r in rows); return "\n".join(out)+"\n"
        body=json.dumps(data,ensure_ascii=False,indent=2)
        if fmt=="md": return "# RED TEAM HUNTING REPORT\n\n```json\n"+body+"\n```\n"
        if fmt=="html": return "<!doctype html><meta charset='utf-8'><title>Redhunt report</title><pre>"+html.escape(body)+"</pre>"
        return body
    @classmethod
    def write(cls,data,fmt,path): Path(path).write_text(cls.render(data,fmt),encoding="utf-8")

class TTLCache:
    def __init__(self,path: Path, ttl=3600): self.path=Path(path); self.ttl=float(ttl); self.path.parent.mkdir(parents=True,exist_ok=True)
    def get(self,key):
        if not self.path.exists(): return None
        try:
            data=json.loads(self.path.read_text(encoding="utf-8")); item=data.get(hashlib.sha256(key.encode()).hexdigest())
            if item and time.time()-item["created"] <= self.ttl: return item["value"]
        except (OSError,ValueError,KeyError,TypeError): return None
        return None
    def set(self,key,value):
        data={}
        if self.path.exists():
            try: data=json.loads(self.path.read_text(encoding="utf-8"))
            except (OSError,ValueError): data={}
        data[hashlib.sha256(key.encode()).hexdigest()]={"created":time.time(),"value":value}; self.path.write_text(json.dumps(data,ensure_ascii=False),encoding="utf-8")

class PluginLoader:
    def __init__(self, directory=Path("plugins")): self.directory=Path(directory)
    def discover(self): return sorted(self.directory.glob("*/plugin.yaml")) if self.directory.exists() else []
    def load(self, plugin_dir):
        path=Path(plugin_dir)/"main.py"
        if not path.is_file(): raise ValueError("main.py plugin tidak ditemukan")
        spec=importlib.util.spec_from_file_location("redhunt_plugin",path); module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        plugin=getattr(module,"Plugin",None)
        if plugin is None or not callable(getattr(plugin,"run",None)): raise ValueError("Plugin harus menyediakan class Plugin dengan run(context)")
        return plugin()

def redact(text: str) -> str:
    return re.sub(r"(?i)(authorization|cookie|api[-_]?key|token|password|secret)(\s*[:=]\s*)\S+",r"\1\2[REDACTED]",text)

def run_external(binary: str,args: list[str],timeout=30):
    if not shutil.which(binary): return {"status":"SKIPPED","reason":f"{binary} tidak tersedia"}
    try:
        p=subprocess.run([binary,*args],capture_output=True,text=True,timeout=timeout,check=False)
        return {"status":"COMPLETED" if p.returncode==0 else "FAILED","returncode":p.returncode,"stdout":redact(p.stdout),"stderr":redact(p.stderr)}
    except subprocess.TimeoutExpired: return {"status":"FAILED","reason":"timeout"}
