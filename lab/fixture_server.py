#!/usr/bin/env python3
"""Local-only training fixture for redhunt integration tests.

Binds exclusively to 127.0.0.1. It intentionally exposes observable test markers
such as missing security headers, a CORS wildcard, OpenAPI, GraphQL GET, robots,
sitemap, security.txt, and harmless reflected marker behavior. It never stores
credentials and never contacts an external service.
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse
import json

HOST, PORT = "127.0.0.1", 18080

class Handler(BaseHTTPRequestHandler):
    server_version = "RedHuntLab/1.0"
    def _send(self, code=200, body="", content_type="text/html", extra=None):
        raw=body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type",content_type)
        self.send_header("Content-Length",str(len(raw)))
        for key,value in (extra or {}).items(): self.send_header(key,value)
        self.end_headers(); self.wfile.write(raw)
    def do_OPTIONS(self):
        self._send(204,"",extra={"Access-Control-Allow-Origin":"*","Access-Control-Allow-Methods":"GET, OPTIONS"})
    def do_GET(self):
        parsed=urlparse(self.path); query=parse_qs(parsed.query)
        if parsed.path=="/":
            marker=query.get("q",[""])[0]
            body="""<!doctype html><html><head><title>RedHunt Lab</title><script src='/static/app.js'></script></head><body><h1>Authorized fixture</h1><a href='/api/docs'>documentation</a><a href='/graphql'>graphql</a><a href='/debug'>debug</a><p>%s</p></body></html>""" % marker
            self._send(200,body,extra={"Set-Cookie":"lab-session=fixture; Secure; HttpOnly; SameSite=Lax"})
        elif parsed.path=="/api/docs":
            self._send(200,json.dumps({"openapi":"3.0.0","info":{"title":"RedHunt Lab","version":"1"},"paths":{"/api/items":{"get":{}}}}),"application/json")
        elif parsed.path=="/graphql": self._send(200,'{"data":null}',"application/json")
        elif parsed.path=="/robots.txt": self._send(200,"User-agent: *\nDisallow: /admin\nSitemap: http://127.0.0.1:18080/sitemap.xml\n","text/plain")
        elif parsed.path=="/sitemap.xml": self._send(200,"<?xml version='1.0'?><urlset><url><loc>http://127.0.0.1:18080/</loc></url></urlset>","application/xml")
        elif parsed.path=="/.well-known/security.txt": self._send(200,"Contact: mailto:security@example.invalid\nExpires: 2030-01-01T00:00:00Z\n","text/plain")
        elif parsed.path=="/static/app.js": self._send(200,"const endpoint='/api/items'; fetch(endpoint);","application/javascript")
        elif parsed.path=="/debug": self._send(200,"debug=true environment=fixture", "text/plain")
        else: self._send(404,"not found")
    def log_message(self, fmt, *args): pass

if __name__ == "__main__":
    print(f"RedHunt lab listening on http://{HOST}:{PORT}")
    HTTPServer((HOST,PORT),Handler).serve_forever()
