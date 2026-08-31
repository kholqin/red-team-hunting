#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
from redhunt.catalog import FEATURES
from redhunt.dispatch import execute


def main():
    results=[]
    for feature in FEATURES:
        try:
            item=execute(feature.id)
        except Exception as exc:
            item={"id":feature.id,"name":feature.name,"status":"ERROR","evidence":{"error":str(exc)}}
        results.append(item)
    report={"total":len(results),"errors":sum(x.get("status")=="ERROR" for x in results),"results":results}
    output=Path("reports/feature-dispatch-audit.json")
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(report,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    print(json.dumps({"total":report["total"],"errors":report["errors"],"output":str(output)}))
    return 1 if report["errors"] else 0

if __name__ == "__main__":
    raise SystemExit(main())
