from __future__ import annotations

import os
import sys
from .catalog import FEATURES

RESET="\033[0m"
COLORS={"green":"\033[92m","yellow":"\033[93m","pink":"\033[95m","cyan":"\033[96m","blue":"\033[94m"}


def ansi(text: str, color: str = "") -> str:
    if os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        return text
    return f"{COLORS.get(color, '')}{text}{RESET if color else ''}"


def clear():
    if not os.environ.get("REDHUNT_NO_CLEAR") and sys.stdout.isatty():
        print("\033[2J\033[H", end="")


def banner(version="0.1.0"):
    clear()
    print(ansi("  ____  _____ ____    _____ _____    _    __  __", "green"))
    print(ansi(" |  _ \\| ____|  _ \\  |_   _| ____|  / \\  |  \\/  |", "green"))
    print(ansi(" | |_) |  _| | | | |   | | |  _|   / _ \\ | |\\/| |", "yellow"))
    print(ansi(" |  _ <| |___| |_| |   | | | |___ / ___ \\| |  | |", "yellow"))
    print(ansi(" |_| \\_\\_____|____/    |_| |_____/ _/   \\_\\_|  |_|", "pink"))
    print(ansi(f"                 [v{version}] [By M4zk1pL4y Scurity]", "pink"))
    print(ansi("         AUTHORIZED SECURITY RESEARCH • SAFE MODE • 120 FEATURES", "cyan"))
    print()


def _item(feature):
    color={"BUG_BOUNTY":"green","OSINT":"yellow","REVERSE":"pink"}[feature.category]
    label=f"[{feature.id}] {feature.name}"
    if len(label)>30: label=label[:27]+"..."
    return ansi(label.ljust(34), color)


def menu():
    print(ansi("┌──────────────────────────────────┬──────────────────────────────────┬──────────────────────────────────┐", "blue"))
    print(ansi("│ BUG BOUNTY                        │ OSINT                            │ REVERSE ENGINEERING              │", "blue"))
    print(ansi("├──────────────────────────────────┼──────────────────────────────────┼──────────────────────────────────┤", "blue"))
    groups=[[f for f in FEATURES if f.category==cat] for cat in ("BUG_BOUNTY","OSINT","REVERSE")]
    for i in range(max(map(len,groups))):
        cells=[_item(group[i]) if i<len(group) else "".ljust(34) for group in groups]
        print("│ "+"│ ".join(cells)+"│")
    print(ansi("└──────────────────────────────────┴──────────────────────────────────┴──────────────────────────────────┘", "blue"))
    print(ansi("[a] About    [s] Saved    [r] Recon    [b] Bug Bounty    [o] OSINT    [v] Reverse    [x] Main Menu    [0] Exit", "pink"))
    print(ansi("Status: SAFE MODE • Scope enforcement aktif • Finding hanya dari evidence aktual", "cyan"))


def feature_summary():
    counts={}
    for f in FEATURES:
        counts.setdefault(f.category,{"total":0,"available":0,"planned":0})
        counts[f.category]["total"]+=1
        counts[f.category]["available"]+=f.status=="AVAILABLE"
        counts[f.category]["planned"]+=f.status=="PLANNED"
    return counts
