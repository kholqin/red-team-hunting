from __future__ import annotations

import os, shutil, sys
from .catalog import FEATURES


def _color(code, text):
    if os.environ.get("NO_COLOR") or not sys.stdout.isatty(): return text
    return f"\033[{code}m{text}\033[0m"


def banner(version="0.1.0"):
    width=max(72,min(shutil.get_terminal_size((100,24)).columns,120))
    title="RED TEAM HUNTING"
    print(_color("96", "╔"+"═"*(width-2)+"╗"))
    print(_color("96", "║"+title.center(width-2)+"║"))
    print(_color("95", "║"+"M4zk1pL4y Scurity".center(width-2)+"║"))
    print(_color("93", "║"+"AUTHORIZED BUG BOUNTY & SECURITY RESEARCH".center(width-2)+"║"))
    print(_color("96", "║"+(f"[v{version}] [SAFE MODE] [120 FEATURE CATALOG]").center(width-2)+"║"))
    print(_color("96", "╚"+"═"*(width-2)+"╝"))


def menu():
    print(_color("94", "\n┌─────┬──────────────────────────────────────────────────────────────┐"))
    print(_color("94", "│ ID  │ MODUL                                                        │"))
    print(_color("94", "├─────┼──────────────────────────────────────────────────────────────┤"))
    for feature in FEATURES:
        prefix={"BUG_BOUNTY":"BB","OSINT":"OS","REVERSE":"RE"}[feature.category]
        status=_color("92",feature.status) if feature.status=="AVAILABLE" else _color("93",feature.status)
        print(f"│ {feature.id:<3} │ {feature.name:<48} {status:<13}│")
    print(_color("94", "└─────┴──────────────────────────────────────────────────────────────┘"))
    print(_color("95", "[r] Recon  [b] Bug bounty  [o] OSINT  [v] Reverse  [q] Keluar"))


def feature_summary():
    counts={}
    for f in FEATURES:
        counts.setdefault(f.category,{"total":0,"available":0,"planned":0}); counts[f.category]["total"]+=1; counts[f.category]["available"]+=f.status=="AVAILABLE"; counts[f.category]["planned"]+=f.status=="PLANNED"
    return counts
