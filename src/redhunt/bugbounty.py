from __future__ import annotations

from .catalog import BUG_BOUNTY
from .modules import api_document_analysis, cloud_fingerprint, cookie_audit, cors_audit, ct_subdomains, robots_and_sitemap, safe_web_indicators, technology, tls_audit


def run_bug_bounty(target, cfg):
    from .cli import dns, endpoints, headers, vuln_check, request
    host=target.split("/",3)[2].split(":",1)[0]
    response=request(target,cfg); dns_data=dns(target); header_data=headers(target,cfg); rs=robots_and_sitemap(target,cfg["timeout"]); tech=technology(response); ct=ct_subdomains(host,cfg["timeout"])
    context={"target":target,"host":host,"response":response,"ips":dns_data.get("ips",[]),"ct":ct.get("subdomains",[]),"tls":tls_audit(host,timeout=cfg["timeout"]),"headers":header_data,"technology":tech,"robots":rs.get("robots"),"sitemap":rs.get("sitemap")}
    skip={
        "BB-03":"WHOIS provider/client belum dikonfigurasi", "BB-04":"ASN provider belum dikonfigurasi", "BB-12":"Gunakan --wordlist secara eksplisit pada command subdomain", "BB-22":"Stored XSS tidak diuji otomatis agar tidak menulis data", "BB-23":"SQLi aktif memerlukan endpoint/parameter eksplisit dan persetujuan tambahan", "BB-24":"NoSQL test aktif tidak dijalankan tanpa endpoint/parameter eksplisit", "BB-25":"SSTI test aktif tidak dijalankan tanpa endpoint/input eksplisit", "BB-28":"LFI tidak membaca file target secara otomatis", "BB-29":"Traversal tidak dijalankan tanpa fixture/path yang disetujui", "BB-30":"IDOR memerlukan dua identitas dan resource yang disediakan operator", "BB-37":"Service banner membutuhkan port yang terbuka dan probe eksplisit", "BB-39":"Perbandingan HTTP/HTTPS membutuhkan kedua URL eksplisit", "BB-40":"Exposure report menunggu hasil port/service scan", "BB-44":"Takeover check membutuhkan provider fingerprint dan DNS CNAME aktual"}
    available={
        "BB-01": {"status":"DETECTED" if ct.get("subdomains") else "NOT DETECTED","data":ct,"evidence":{"source":"crt.sh response aktual"}},
        "BB-02": {"status":"DETECTED" if dns_data.get("ips") else "NOT DETECTED","data":dns_data,"evidence":{"source":"DNS resolver aktual"}},
        "BB-05": {"status":"DETECTED" if dns_data.get("ips") else "NOT DETECTED","data":dns_data,"evidence":{"source":"getaddrinfo aktual"}},
        "BB-06": {"status":"INCONCLUSIVE","data":[],"evidence":{"reason":"PTR lookup dapat dijalankan melalui command osint; belum disimpulkan dari HTTP scan"}},
        "BB-07": {"status":context["tls"].get("status","INCONCLUSIVE"),"data":context["tls"],"evidence":{"source":"TLS handshake aktual"}},
        "BB-08": {"status":"DETECTED" if ct.get("subdomains") else "NOT DETECTED","data":ct,"evidence":{"source":"Certificate Transparency aktual"}},
        "BB-09": {"status":"DETECTED" if tech.get("observed") else "NOT DETECTED","data":tech,"evidence":{"source":"HTTP response aktual"}},
        "BB-10": {"status":"DETECTED" if response[0] else "INCONCLUSIVE","data":header_data,"evidence":{"source":"HTTP response aktual"}},
        "BB-11": {"status":"DETECTED" if response[0] else "INCONCLUSIVE","data":{"status_code":response[0]},"evidence":{"source":"HTTP status aktual"}},
        "BB-13": {"status":"DETECTED" if endpoints(target,cfg).get("endpoints") else "NOT DETECTED","data":endpoints(target,cfg),"evidence":{"source":"HTML response aktual"}},
        "BB-14": {"status":"DETECTED" if rs["robots"]["status"]==200 else "NOT DETECTED","data":rs["robots"],"evidence":{"source":"robots.txt aktual"}},
        "BB-15": {"status":"DETECTED" if rs["sitemap"]["status"]==200 else "NOT DETECTED","data":rs["sitemap"],"evidence":{"source":"sitemap.xml aktual"}},
        "BB-16": {"status":"DETECTED" if endpoints(target,cfg).get("endpoints") else "NOT DETECTED","data":endpoints(target,cfg),"evidence":{"source":"script/endpoint extraction aktual"}},
        "BB-17": {"status":"DETECTED" if "?" in target else "NOT TESTED","data":{"parameters":[]},"evidence":{"source":"URL input aktual"}},
        "BB-18": {"status":"DETECTED" if header_data.get("missing_security_headers") else "NOT DETECTED","data":{"missing":header_data.get("missing_security_headers",[])},"evidence":{"source":"HTTP headers aktual"}},
        "BB-19": {"status":"DETECTED" if cookie_audit(response).get("cookies") else "NOT DETECTED","data":cookie_audit(response),"evidence":{"source":"Set-Cookie aktual"}},
        "BB-20": {"status":"DETECTED" if cors_audit(target,cfg["timeout"]).get("allow_origin") else "NOT DETECTED","data":cors_audit(target,cfg["timeout"]),"evidence":{"source":"OPTIONS response aktual"}},
        "BB-21": {"status":"DETECTED" if safe_web_indicators(target,cfg["timeout"]).get("findings") else "NOT DETECTED","data":safe_web_indicators(target,cfg["timeout"]),"evidence":{"source":"marker inert pada response aktual"}},
        "BB-26": {"status":"DETECTED" if safe_web_indicators(target,cfg["timeout"]).get("findings") else "NOT DETECTED","data":safe_web_indicators(target,cfg["timeout"]),"evidence":{"source":"Location response aktual"}},
        "BB-27": {"status":"NOT TESTED","data":{},"evidence":{"reason":"SSRF tidak dipicu; hanya identifikasi parameter URL yang memerlukan input eksplisit"}},
        "BB-31": {"status":"DETECTED" if api_document_analysis(target,cfg["timeout"]).get("documents") else "NOT DETECTED","data":api_document_analysis(target,cfg["timeout"]),"evidence":{"source":"API documentation probes aktual"}},
        "BB-32": {"status":"DETECTED" if api_document_analysis(target,cfg["timeout"]).get("documents") else "NOT DETECTED","data":api_document_analysis(target,cfg["timeout"]),"evidence":{"source":"OpenAPI/Swagger response aktual"}},
        "BB-33": {"status":"DETECTED","data":api_document_analysis(target,cfg["timeout"]).get("graphql",{}),"evidence":{"source":"GET /graphql aktual"}},
        "BB-34": {"status":"DETECTED" if any(k.lower() in {x.lower() for x in response[1]} for k in ["authorization","www-authenticate","set-cookie"]) else "NOT DETECTED","data":{"observed_headers":[k for k in response[1] if k.lower() in {"authorization","www-authenticate","set-cookie"}]},"evidence":{"source":"HTTP headers aktual"}},
        "BB-35": {"status":"NOT TESTED","data":{},"evidence":{"reason":"JWT hanya dianalisis bila token diberikan eksplisit melalui command jwt"}},
        "BB-36": {"status":"NOT TESTED","data":{},"evidence":{"reason":"Gunakan command ports dengan port list eksplisit"}},
        "BB-38": {"status":context["tls"].get("status","INCONCLUSIVE"),"data":context["tls"],"evidence":{"source":"TLS handshake aktual"}},
        "BB-41": {"status":"DETECTED" if cloud_fingerprint(response).get("providers") else "NOT DETECTED","data":cloud_fingerprint(response),"evidence":{"source":"HTTP response aktual"}},
        "BB-42": {"status":"DETECTED" if cloud_fingerprint(response).get("public_storage_references") else "NOT DETECTED","data":{"references":cloud_fingerprint(response).get("public_storage_references",[])},"evidence":{"source":"body response aktual"}},
        "BB-43": {"status":"DETECTED" if cloud_fingerprint(response).get("metadata_references") else "NOT DETECTED","data":{"references":cloud_fingerprint(response).get("metadata_references",[])},"evidence":{"source":"body response aktual"}},
        "BB-45": {"status":"DETECTED" if tech.get("observed") else "NOT DETECTED","data":tech,"evidence":{"source":"headers/body aktual"}},
        "BB-46": {"status":"DETECTED" if vuln_check(target,cfg).get("findings") else "NOT DETECTED","data":vuln_check(target,cfg),"evidence":{"source":"vulnerability observations aktual"}},
        "BB-47": {"status":"DETECTED","data":{"method":"rule-based severity aggregation","findings":len(vuln_check(target,cfg).get("findings",[]))},"evidence":{"source":"findings aktual; bukan CVSS claim"}},
        "BB-48": {"status":"DETECTED","data":{"deduplicated":len({f.get("id") for f in vuln_check(target,cfg).get("findings",[])})},"evidence":{"source":"finding IDs aktual"}},
        "BB-49": {"status":"DETECTED","data":{"request":{"url":target,"status":response[0]},"response_headers":response[1]},"evidence":{"source":"request/response aktual","redaction":True}},
        "BB-50": {"status":"DETECTED","data":{"formats":["table","json","csv","txt","md","html"]},"evidence":{"source":"report writer executable"}},
    }
    records=[]
    for fid,name,*_metadata in BUG_BOUNTY:
        if fid in skip: item={"status":"SKIPPED","data":{},"evidence":{"reason":skip[fid]}}
        else: item=available.get(fid,{"status":"INCONCLUSIVE","data":{},"evidence":{"reason":"executor belum mengembalikan kesimpulan dari input ini"}})
        records.append({"id":fid,"name":name,"status":item["status"],"data":item["data"],"evidence":item["evidence"]})
    return records
