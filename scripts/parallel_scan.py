#!/usr/bin/env python3
"""Run redhunt bug bounty and OSINT modules in parallel for explicitly scoped targets.

This runner is intentionally bounded and non-destructive. It never bypasses the
redhunt CLI's own validation and stores one evidence report per target/module.
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import logging
import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

LOG = logging.getLogger("redhunt.parallel")
_STOP = False


def on_signal(signum, _frame):
    global _STOP
    _STOP = True
    LOG.warning("Cancellation requested (signal %s); no new jobs will start.", signum)


def load_scope(path: Path) -> list[str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    allowed = data.get("allowed", [])
    if not isinstance(allowed, list) or not allowed:
        raise ValueError("scope file must contain a non-empty JSON array named 'allowed'")
    return [str(x).strip().lower() for x in allowed if str(x).strip()]


def normalize_target(raw: str) -> str:
    value = raw.strip()
    if not value or value.startswith("-"):
        raise ValueError("empty or invalid target")
    if "://" not in value:
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"invalid HTTP(S) target: {raw}")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("targets may not contain credentials, query strings, or fragments")
    if not re.fullmatch(r"[A-Za-z0-9.-]+", parsed.hostname):
        raise ValueError(f"invalid hostname: {parsed.hostname}")
    return value.rstrip("/")


def in_scope(target: str, allowed: list[str]) -> bool:
    host = urlparse(target).hostname.lower()
    for rule in allowed:
        rule = rule.removeprefix("*.")
        if host == rule or host.endswith("." + rule):
            return True
    return False


def read_targets(path: Path, allowed: list[str], limit: int) -> list[str]:
    seen = set(); targets = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        target = normalize_target(line)
        if not in_scope(target, allowed):
            raise ValueError(f"target outside scope: {target}")
        if target not in seen:
            seen.add(target); targets.append(target)
    if not targets:
        raise ValueError("targets file has no usable targets")
    if len(targets) > limit:
        raise ValueError(f"target count {len(targets)} exceeds --max-targets {limit}")
    return targets


def run_module(repo: Path, target: str, module: str, output_dir: Path, timeout: int) -> dict:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", urlparse(target).hostname or "target")
    out = output_dir / f"{safe}-{module}.json"
    command = [sys.executable, "-m", "redhunt", module, target, "--output", "json", "--out", str(out)]
    started = time.time()
    LOG.info("START target=%s module=%s", target, module)
    try:
        completed = subprocess.run(command, cwd=repo, env={**os.environ, "PYTHONPATH": str(repo / "src")}, text=True, capture_output=True, timeout=timeout)
        status = "COMPLETED" if completed.returncode == 0 else "FAILED"
        return {"target":target,"module":module,"status":status,"returncode":completed.returncode,"elapsed_seconds":round(time.time()-started,3),"report":str(out),"stdout":completed.stdout[-2000:],"stderr":completed.stderr[-2000:]}
    except subprocess.TimeoutExpired as exc:
        return {"target":target,"module":module,"status":"TIMEOUT","returncode":None,"elapsed_seconds":round(time.time()-started,3),"report":str(out),"stdout":str(exc.stdout or "")[-2000:],"stderr":str(exc.stderr or "")[-2000:]}
    except Exception as exc:
        LOG.exception("ERROR target=%s module=%s", target, module)
        return {"target":target,"module":module,"status":"ERROR","returncode":None,"elapsed_seconds":round(time.time()-started,3),"report":str(out),"error":str(exc)}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Bounded parallel runner for authorized redhunt bug bounty and OSINT scans")
    parser.add_argument("--targets", type=Path, required=True, help="newline-separated HTTP(S) targets")
    parser.add_argument("--scope", type=Path, required=True, help="JSON scope file, e.g. {\"allowed\":[\"example.com\"]}")
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output-dir", type=Path, default=Path("reports/parallel"))
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--module-timeout", type=int, default=180)
    parser.add_argument("--max-targets", type=int, default=25)
    args = parser.parse_args(argv)
    if not 1 <= args.workers <= 8 or not 10 <= args.module_timeout <= 900 or not 1 <= args.max_targets <= 100:
        parser.error("workers must be 1..8, module-timeout 10..900, max-targets 1..100")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    signal.signal(signal.SIGINT, on_signal); signal.signal(signal.SIGTERM, on_signal)
    try:
        allowed = load_scope(args.scope)
        targets = read_targets(args.targets, allowed, args.max_targets)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        LOG.error("INPUT_REJECTED: %s", exc); return 2
    args.output_dir.mkdir(parents=True, exist_ok=True)
    jobs = [(target,module) for target in targets for module in ("bugbounty", "osint")]
    results = []
    with cf.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = []
        for target,module in jobs:
            if _STOP: break
            futures.append(pool.submit(run_module,args.repo,target,module,args.output_dir,args.module_timeout))
        try:
            for future in cf.as_completed(futures):
                results.append(future.result())
        except KeyboardInterrupt:
            on_signal(signal.SIGINT, None)
            for future in futures: future.cancel()
    manifest={"status":"CANCELLED" if _STOP else "COMPLETED","targets":targets,"modules":["bugbounty","osint"],"worker_limit":args.workers,"results":results}
    manifest_path=args.output_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    failed=[r for r in results if r["status"] != "COMPLETED"]
    LOG.info("FINISHED targets=%d jobs=%d failed_or_incomplete=%d manifest=%s",len(targets),len(results),len(failed),manifest_path)
    return 1 if failed else 0

if __name__ == "__main__":
    raise SystemExit(main())
