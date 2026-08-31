import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from redhunt.cli import vuln_check


class FixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"local fixture")

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

    def log_message(self, *_):
        pass


def test_real_header_findings_from_local_fixture():
    server = HTTPServer(("127.0.0.1", 0), FixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = vuln_check(f"http://127.0.0.1:{server.server_port}", {"timeout": 2})
        assert result["status"] == "DETECTED"
        assert result["findings"]
        assert all("Respons aktual" in item["evidence"] or "Header" in item["evidence"] for item in result["findings"])
    finally:
        server.shutdown()
        thread.join(timeout=2)
