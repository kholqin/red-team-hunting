from __future__ import annotations

import hashlib, json, re
from dataclasses import asdict, dataclass
from pathlib import Path

@dataclass
class SourceFinding:
    rule_id: str
    severity: str
    confidence: int
    path: str
    line: int
    language: str
    evidence: str
    remediation: str

LANGUAGE_EXTENSIONS={
    "Java": {".java"}, "JavaScript": {".js",".jsx",".mjs",".cjs"}, "TypeScript": {".ts",".tsx"},
    "PHP": {".php"}, "Laravel": {".blade.php"}, "C": {".c",".h"}, "C++": {".cc",".cpp",".cxx",".hpp",".hh"},
    "C#": {".cs"}, "Python": {".py",".pyi"}, "Ruby": {".rb"}, "Go": {".go"}, "Rust": {".rs"},
    "Kotlin": {".kt",".kts"}, "Swift": {".swift"}, "Dart": {".dart"}, "R": {".r",".R"},
    "MATLAB": {".m"}, "Lua": {".lua"}, "Perl": {".pl",".pm"}, "Objective-C": {".mm"},
    "Scala": {".scala"}, "Elixir": {".ex",".exs"}, "Haskell": {".hs",".lhs"}, "Erlang": {".erl",".hrl"},
    "Julia": {".jl"}, "Fortran": {".f",".f90",".f95",".for"}, "COBOL": {".cob",".cbl"},
    "Assembly": {".asm",".s",".S"}, "SQL": {".sql",".pgsql",".psql"}, "PL/SQL": {".pls",".pkb",".pks"},
    "T-SQL": {".tsql"}, "PL/pgSQL": {".pgsql"}, "Solidity": {".sol"}, "Vyper": {".vy"},
    "Cairo": {".cairo"}, "GDScript": {".gd"}, "Visual Basic": {".vb"}, "F#": {".fs",".fsi",".fsx"},
    "Zig": {".zig"}, "D": {".d"}, "Ada": {".ada",".adb",".ads"}, "Nim": {".nim"},
    "Lisp": {".lisp",".lsp"}, "Clojure": {".clj",".cljs",".cljc"}, "OCaml": {".ml",".mli"},
    "Move": {".move"}, "Cryptography config": {".pem",".key",".crt"}, "HTML": {".html",".htm"},
}
SPECIAL_FILES={"go.mod":"Go","go.sum":"Go","composer.json":"PHP/Laravel","package.json":"JavaScript/TypeScript","pubspec.yaml":"Dart","Cargo.toml":"Rust","Gemfile":"Ruby","requirements.txt":"Python","pom.xml":"Java","build.gradle":"Java/Kotlin","mix.exs":"Elixir"}
PATTERNS=[
    ("SEC-SECRET-001","HIGH",95,re.compile(r"(?i)(api[_-]?key|secret|password|passwd|private[_-]?key|access[_-]?token)\s*[:=]\s*['\"]?[^\s'\"]{8,}"),"Pindahkan secret ke secret manager atau environment variable dan rotasi jika sudah terekspos."),
    ("SEC-EXEC-001","HIGH",90,re.compile(r"\b(eval|exec|system|popen|passthru|shell_exec|Runtime\.getRuntime\(\)\.exec|os\.system|subprocess\.\w+|Process\.Start)\b"),"Validasi input, gunakan API tanpa shell, dan batasi command melalui allowlist."),
    ("SEC-DESERIAL-001","HIGH",85,re.compile(r"(?i)(pickle\.loads|yaml\.load\s*\(|ObjectInputStream|unserialize\s*\(|BinaryFormatter|Marshal\.load)"),"Gunakan format data aman dan validasi tipe serta sumber input sebelum deserialisasi."),
    ("SEC-CRYPTO-001","MEDIUM",88,re.compile(r"(?i)(md5|sha1|des|rc4|ecb|Math\.random)"),"Gunakan primitive modern dan mode authenticated encryption sesuai threat model."),
    ("SEC-SQL-001","MEDIUM",82,re.compile(r"(?i)(select|insert|update|delete)\s+.*(\+|\%s|\$\{|\.format\(|f['\"]|concat)"),"Gunakan prepared statement atau query builder; jangan menyusun query dari input mentah."),
    ("SEC-HTTP-001","MEDIUM",80,re.compile(r"(?i)(http://|verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify)"),"Gunakan TLS tervalidasi dan hindari koneksi HTTP untuk data sensitif."),
    ("SEC-HTML-001","MEDIUM",82,re.compile(r"(?i)(innerHTML\s*=|document\.write\s*\(|dangerouslySetInnerHTML)"),"Gunakan sink yang melakukan escaping dan Content Security Policy."),
    ("SEC-SOL-001","HIGH",82,re.compile(r"(?i)(delegatecall|tx\.origin|call\s*\{|selfdestruct|\.call\{)"),"Tinjau kontrol akses, checks-effects-interactions, dan audit smart contract."),
]

def detect_language(path: Path):
    if path.name in SPECIAL_FILES: return SPECIAL_FILES[path.name]
    lower=path.name.lower()
    for language,extensions in LANGUAGE_EXTENSIONS.items():
        if any(lower.endswith(ext.lower()) for ext in extensions): return language
    return "Unknown"

def _snippet(line):
    line=re.sub(r"(?i)(password|secret|token|api[_-]?key|private[_-]?key)(\s*[:=]\s*)['\"]?[^\s'\"]+",r"\1\2[REDACTED]",line)
    return line.strip()[:240]

def analyze_file(path: str, max_bytes=5_000_000):
    p=Path(path)
    if not p.is_file(): return {"status":"FAILED","path":str(p),"error":"file tidak ditemukan"}
    if p.stat().st_size>max_bytes: return {"status":"SKIPPED","path":str(p),"reason":"file melebihi batas ukuran"}
    language=detect_language(p); raw=p.read_bytes(); text=raw.decode("utf-8","replace"); lines=text.splitlines(); findings=[]
    for number,line in enumerate(lines,1):
        for rule,severity,confidence,pattern,remediation in PATTERNS:
            if pattern.search(line): findings.append(asdict(SourceFinding(rule,severity,confidence,str(p),number,language,_snippet(line),remediation)))
    imports=[]; symbols=[]
    for number,line in enumerate(lines,1):
        if re.search(r"(?i)^\s*(import|from|require|use|include|open|extern crate|package)\b",line): imports.append({"line":number,"text":_snippet(line)})
        if re.search(r"(?i)\b(class|interface|struct|enum|def|func|function|fn|sub|module|contract|program)\b",line): symbols.append({"line":number,"text":_snippet(line)})
    return {"status":"COMPLETED","path":str(p),"language":language,"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest(),"lines":len(lines),"imports":imports[:500],"symbols":symbols[:500],"findings":findings,"finding_count":len(findings)}

def analyze_path(path: str):
    p=Path(path)
    if p.is_file(): return [analyze_file(str(p))]
    if not p.is_dir(): return [{"status":"FAILED","path":str(p),"error":"path tidak ditemukan"}]
    results=[]
    for child in sorted(p.rglob("*")):
        if child.is_file() and not any(part in {".git","node_modules","vendor",".venv","target","build","dist"} for part in child.parts):
            language=detect_language(child)
            if language!="Unknown": results.append(analyze_file(str(child)))
    return results[:5000]
