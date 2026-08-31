# Matriks Input dan Dependency 120 Fitur

Dokumen ini menjelaskan input minimum dan dependency setiap fitur. **Built-in** berarti tersedia dari Python standard library atau engine internal. **Opsional** berarti fitur dapat mengembalikan `SKIPPED` jika dependency tidak ditemukan. **Provider/API** berarti operator harus memasukkan endpoint atau credential resmi. Tidak ada dependency yang boleh diganti dengan output palsu.

## Ringkasan dependency

| Jenis | Contoh |
|---|---|
| Built-in | Python 3.10+, `urllib`, `ssl`, `socket`, `hashlib`, `sqlite3`, parser HTML internal |
| CLI opsional | `nmap`, `nuclei`, `subfinder`, `amass`, `ffuf`, `gobuster`, `masscan`, `jadx`, `apktool`, `radare2` |
| Provider resmi | WHOIS/RDAP, ASN/BGP, GitHub API, CT log, URL archive, breach-reference provider |
| Input khusus | Scope file, wordlist, endpoint, parameter, file PDF/image/binary, dua akun uji |

## 50 Bug Bounty

| ID | Fitur | Input minimum | Dependency |
|---|---|---|---|
| BB-01 | Enumerasi Subdomain | Domain dalam scope | CT log/`crt.sh`, DNS resolver; built-in fallback |
| BB-02 | DNS Enumeration | Domain/hostname | `socket`/DNS resolver built-in |
| BB-03 | WHOIS Lookup | Domain | WHOIS/RDAP client atau provider resmi |
| BB-04 | ASN Discovery | IP/domain ter-resolve | ASN/RDAP/BGP provider resmi |
| BB-05 | IP Discovery | Domain/hostname | `socket.getaddrinfo` |
| BB-06 | Reverse DNS | IP aktual | PTR resolver/socket |
| BB-07 | Certificate Enumeration | Hostname, port TLS | Python `ssl` |
| BB-08 | Certificate Transparency | Domain | CT provider/API publik |
| BB-09 | Technology Fingerprinting | URL dan response HTTP | HTTP client, fingerprint rules internal |
| BB-10 | HTTP Header Analyzer | URL | HTTP client built-in |
| BB-11 | HTTP Status Mapper | URL atau daftar URL | HTTP client, response aktual |
| BB-12 | Directory Discovery | URL + wordlist eksplisit | Wordlist; HTTP client; bounded requests |
| BB-13 | Endpoint Discovery | URL | Crawler internal |
| BB-14 | robots.txt Analyzer | URL/domain | HTTP client |
| BB-15 | sitemap.xml Analyzer | URL/domain | HTTP client/XML parser |
| BB-16 | JavaScript Endpoint Extraction | URL/JS response | HTTP client, tokenizer/regex fallback |
| BB-17 | Parameter Discovery | HTML/JS/OpenAPI/GraphQL input | Crawler dan parser internal |
| BB-18 | Security Header Audit | URL | HTTP client |
| BB-19 | Cookie Security Audit | URL response | HTTP client, `Set-Cookie` parser |
| BB-20 | CORS Analyzer | URL | HTTP `OPTIONS`; target harus mengizinkan request |
| BB-21 | Reflected XSS Detector | URL dengan parameter yang sudah ada | Marker inert, baseline/mutation HTTP |
| BB-22 | Stored XSS Indicator | Endpoint input + akun uji + fixture | Persetujuan write/delete, dua request lifecycle |
| BB-23 | SQL Injection Detection | Endpoint + parameter eksplisit | Baseline/mutation engine; lab/izin active testing |
| BB-24 | NoSQL Injection Indicator | API endpoint + parameter/body schema | Safe mutation engine; lab/izin |
| BB-25 | SSTI Detection | Template parameter eksplisit | Marker inert, baseline comparison |
| BB-26 | Open Redirect Detection | URL + parameter redirect yang ada | HTTP redirect analyzer |
| BB-27 | SSRF Indicator | Parameter URL eksplisit | Callback endpoint milik operator; tidak probe metadata/internal otomatis |
| BB-28 | LFI Indicator | Endpoint/file parameter eksplisit | Fixture file; tidak membaca file sistem target |
| BB-29 | Path Traversal Detection | Path parameter eksplisit | Fixture path; bounded mutation |
| BB-30 | IDOR Candidate Detection | Resource + dua identity context | Dua akun/token uji sah, response differential |
| BB-31 | API Endpoint Discovery | URL | HTTP client, known API paths terbatas |
| BB-32 | OpenAPI Analyzer | URL/spec file OpenAPI | JSON/YAML parser; URL aktual |
| BB-33 | GraphQL Analyzer | URL GraphQL | HTTP GET/OPTIONS; schema hanya jika publik/diizinkan |
| BB-34 | API Authentication Analyzer | API endpoint + request metadata | Token resmi opsional; tidak menebak credential |
| BB-35 | JWT Analyzer | JWT dari input operator/response tersanitasi | Base64/JSON built-in; tidak forgery |
| BB-36 | TCP Port Discovery | Host/IP + port list/range terbatas | `socket`; timeout/concurrency bounded |
| BB-37 | Service Detection | IP:port yang sudah ditemukan | Banner probe bounded; `nmap` opsional |
| BB-38 | TLS Audit | Hostname + port | Python `ssl`, OpenSSL opsional |
| BB-39 | HTTP/HTTPS Comparison | Pasangan URL HTTP dan HTTPS | HTTP client; dua endpoint dalam scope |
| BB-40 | Network Exposure Report | Hasil port/service scan aktual | Collector internal/`nmap` opsional |
| BB-41 | Cloud Asset Fingerprinting | DNS/HTTP response | Fingerprint rules internal |
| BB-42 | Public Storage Indicator | Domain/URL dan response aktual | HTTP/DNS; provider cloud opsional |
| BB-43 | Cloud Metadata Reference Detector | HTML/JS/config response aktual | Static pattern analyzer; redaction |
| BB-44 | Subdomain Takeover Indicator | CNAME + provider response | DNS + provider fingerprint; validasi manual |
| BB-45 | CDN/WAF Detection | DNS/HTTP response | Header/DNS fingerprint rules |
| BB-46 | Vulnerability Correlation Engine | Finding/evidence dari modul lain | Correlation rules internal |
| BB-47 | Risk Scoring | Finding lengkap + evidence | Scoring rules internal; tidak fake CVSS |
| BB-48 | Finding Deduplication | Kumpulan finding | Fingerprint/dedup engine internal |
| BB-49 | Evidence Collector | Request/response/file result | JSON serializer, redaction internal |
| BB-50 | Professional Report Generator | Scan result/session ID | JSON/SQLite/report renderer internal |

## 50 OSINT

| ID | Fitur | Input minimum | Dependency |
|---|---|---|---|
| OS-01 | Domain intelligence | Domain | DNS/HTTP/CT collector |
| OS-02 | Subdomain intelligence | Domain | CT log + DNS resolver |
| OS-03 | WHOIS intelligence | Domain | WHOIS/RDAP provider resmi |
| OS-04 | ASN intelligence | IP/domain | ASN/BGP/RDAP provider |
| OS-05 | IP intelligence | IP aktual | DNS resolver; IP provider opsional |
| OS-06 | Reverse DNS intelligence | IP | PTR/DNS resolver |
| OS-07 | Certificate intelligence | Domain/host | TLS + CT collector |
| OS-08 | Email domain intelligence | Domain + public source | HTTP/source parser; provider opsional |
| OS-09 | Username enumeration | Username eksplisit | Daftar situs publik/provider; rate limit |
| OS-10 | Public profile discovery | Nama/username eksplisit | Sumber publik; tidak mass profiling |
| OS-11 | GitHub repository intelligence | Org/user/repo eksplisit | GitHub API/public HTTP |
| OS-12 | GitHub organization intelligence | Organization name | GitHub API; token resmi opsional |
| OS-13 | Public code search | Query + owner scope | GitHub/code search API resmi |
| OS-14 | Public secret indicator scanning | Repository/source URL atau file | Downloader/parser; redaction |
| OS-15 | Paste-site reference discovery | Domain/query eksplisit | Provider legal/official API; tidak breach scraping |
| OS-16 | Document metadata extraction | URL/path dokumen | `urllib`, file parser |
| OS-17 | PDF metadata analysis | PDF aktual | `pypdf`/`pdfinfo` opsional |
| OS-18 | Image metadata analysis | Image aktual | Pillow/`exiftool` opsional |
| OS-19 | EXIF extraction | JPEG/PNG/TIFF aktual | Pillow/EXIF parser |
| OS-20 | URL intelligence | URL/domain | HTTP client + URL parser |
| OS-21 | Historical URL discovery | Domain | Wayback/URL archive API |
| OS-22 | Archived endpoint discovery | Domain/archive result | Archive API + URL parser |
| OS-23 | Technology intelligence | HTTP response | Fingerprint rules internal |
| OS-24 | CMS detection | HTML/HTTP response | HTML parser + signatures |
| OS-25 | JavaScript library detection | HTML/JS response | JS tokenizer/signatures |
| OS-26 | WAF detection | HTTP response | Header/body fingerprint |
| OS-27 | CDN detection | DNS/HTTP response | DNS/CNAME/header fingerprint |
| OS-28 | Cloud provider detection | DNS/HTTP response | Cloud signature rules |
| OS-29 | Email pattern discovery | Public HTML/source | Email parser + redaction |
| OS-30 | Public contact discovery | Domain/org + public pages | HTTP crawler bounded |
| OS-31 | Organization intelligence | Org/company identifier | Public sources/provider opsional |
| OS-32 | Company domain mapping | Company name | Search/provider resmi; input company |
| OS-33 | Brand/domain correlation | Brand + domain candidates | Public source collector |
| OS-34 | Certificate relationship mapping | CT certificates | CT provider/API |
| OS-35 | IP relationship mapping | IP list | DNS/ASN evidence |
| OS-36 | Subdomain relationship graph | Domain + subdomain list | Graph builder internal |
| OS-37 | URL relationship graph | URL/body/archive result | URL parser + graph builder |
| OS-38 | Asset relationship graph | Domain/IP/URL/CT evidence | Graph builder internal |
| OS-39 | Public breach-reference detection | Domain/email query | Official breach-reference API + key; no credential retrieval |
| OS-40 | Credential exposure indicator | Approved local dataset/provider | Dataset/API resmi; mandatory redaction |
| OS-41 | Repository secret indicator | Repo URL/local checkout | GitHub/API/git; read-only |
| OS-42 | Configuration exposure indicator | Public response/file | HTTP/file parser + secret redaction |
| OS-43 | Backup-file indicator | Explicit URL/path or local fixture | HTTP/file input; no brute-force |
| OS-44 | Debug endpoint discovery | Explicit endpoint list or lab | HTTP client; no unlimited guessing |
| OS-45 | Public documentation discovery | Domain/HTML | HTTP crawler bounded |
| OS-46 | Swagger/OpenAPI discovery | API base URL/spec URL | HTTP + JSON/YAML parser |
| OS-47 | Security.txt discovery | Domain | HTTP client |
| OS-48 | Robots intelligence | Domain | HTTP client |
| OS-49 | Sitemap intelligence | Domain | HTTP/XML parser |
| OS-50 | OSINT correlation engine | Evidence dari collector OSINT | Correlation graph/rules internal |

## 20 Reverse Engineering

| ID | Fitur | Input minimum | Dependency |
|---|---|---|---|
| RE-01 | File Type Detection | File aktual | Python magic/header fallback; `file` opsional |
| RE-02 | Hash Calculator | File aktual | `hashlib` built-in |
| RE-03 | Strings Extraction | File aktual | Byte scanner built-in |
| RE-04 | Entropy Analysis | File aktual | `math`/byte histogram built-in |
| RE-05 | Binary Header Analysis | File aktual | Header parsers internal |
| RE-06 | ELF Analysis | ELF aktual | ELF parser internal/`readelf` opsional |
| RE-07 | PE Analysis | PE aktual | PE parser internal/`pefile` opsional |
| RE-08 | Mach-O Analysis | Mach-O aktual | Mach-O parser internal/otool opsional |
| RE-09 | APK Metadata Analysis | APK aktual | ZIP parser built-in; `aapt` opsional |
| RE-10 | Android Manifest Analysis | APK/AAB aktual | AXML parser/`apktool` opsional |
| RE-11 | DEX Analysis | DEX/APK aktual | DEX parser/`jadx` opsional |
| RE-12 | Java Class Analysis | `.class`/JAR aktual | Java class parser/`javap` opsional |
| RE-13 | Import Analysis | Binary/source aktual | Format parser + strings fallback |
| RE-14 | Export Analysis | Binary/source aktual | Format parser + symbol fallback |
| RE-15 | Section Analysis | ELF/PE/Mach-O aktual | Format-specific parser |
| RE-16 | Symbol Analysis | Binary aktual | Symbol parser/`nm`/Radare2 opsional |
| RE-17 | Embedded URL Extraction | File aktual | Byte/string scanner |
| RE-18 | Embedded IP Extraction | File aktual | Byte/string scanner + IP parser |
| RE-19 | Embedded Secret Indicator | File/source aktual | Pattern scanner + mandatory redaction |
| RE-20 | Static Risk Analysis | File + hasil sub-analyzer | Correlation/risk rules internal |

## Status dependency

Jika input minimum tidak tersedia, executor harus mengembalikan `NOT TESTED` atau `INCONCLUSIVE`. Jika dependency opsional tidak ada, executor harus menggunakan fallback yang aman bila tersedia atau mengembalikan `SKIPPED` dengan nama dependency dan alasan. Tidak ada executor yang boleh mengarang IP, endpoint, finding, confidence, CVSS, atau evidence.
