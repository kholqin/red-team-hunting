from urllib.request import Request, urlopen


class Plugin:
    name = "http-methods"
    version = "0.1.0"

    def run(self, context):
        target = context.get("target")
        timeout = float(context.get("timeout", 10))
        if not target:
            return {"status": "FAILED", "error": "target tidak diberikan"}
        request = Request(target, headers={"User-Agent": "Red-Team-Hunting/0.1.0"}, method="OPTIONS")
        try:
            with urlopen(request, timeout=timeout) as response:
                return {
                    "status": "DETECTED",
                    "http_status": response.status,
                    "allow": response.headers.get("Allow"),
                    "evidence": "Header Allow diperoleh dari respons OPTIONS aktual.",
                }
        except Exception as exc:
            return {"status": "FAILED", "error": str(exc)}
