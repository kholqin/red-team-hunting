from __future__ import annotations

import os
import shutil
import sys
from .catalog import FEATURES

RESET="\033[0m"
COLORS={"green":"\033[92m","yellow":"\033[93m","pink":"\033[95m","cyan":"\033[96m","blue":"\033[94m","red":"\033[91m","white":"\033[97m"}


def ansi(text: str, color: str = "") -> str:
    if os.environ.get("NO_COLOR") or not sys.stdout.isatty(): return text
    return f"{COLORS.get(color, '')}{text}{RESET if color else ''}"


def clear():
    if not os.environ.get("REDHUNT_NO_CLEAR") and sys.stdout.isatty(): print("\033[2J\033[H", end="")


def _box(lines: list[str], width: int, color: str) -> None:
    print(ansi("╔"+"═"*width+"╗",color))
    for line in lines: print(ansi("║"+line[:width].center(width)+"║",color))
    print(ansi("╚"+"═"*width+"╝",color))


def banner(version="0.1.0"):
    clear()
    width=shutil.get_terminal_size((120,30)).columns
    box=min(max(width-4,72),116)
    _box(["██████╗ ███████╗██████╗     ████████╗███████╗ █████╗ ███╗   ███╗",
          "██╔══██╗██╔════╝██╔══██╗    ╚══██╔══╝██╔════╝██╔══██╗████╗ ████║",
          "██████╔╝█████╗  ██║  ██║       ██║   █████╗  ███████║██╔████╔██║",
          "██╔══██╗██╔══╝  ██║  ██║       ██║   ██╔══╝  ██╔══██║██║╚██╔╝██║",
          "██║  ██║███████╗██████╔╝       ██║   ███████╗██║  ██║██║ ╚═╝ ██║",
          "╚═╝  ╚═╝╚══════╝╚═════╝        ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝"],box,"green")
    print(ansi("M4zk1pLay Hunting  //  RED TEAM SECURITY RESEARCH", "pink"))
    print(ansi(f"red_team Tools  |  v{version}  |  120 ACTIVE MODULES", "cyan"))
    print()
    _box(["DISCLAIMER",
          "Gunakan hanya pada aset milik sendiri atau target dengan izin tertulis.",
          "Mode aman: tidak ada credential theft, DoS, persistence, atau aksi destruktif.",
          "Finding harus berasal dari evidence aktual; hasil yang tidak cukup tetap INCONCLUSIVE."],box,"red")
    print(ansi("[ SAFE MODE: ON ]  [ SCOPE ENFORCEMENT: ON ]  [ EVIDENCE-BASED: ON ]", "cyan"))
    print()


def _numbered(): return [(index+1,feature) for index,feature in enumerate(FEATURES)]


def _item(number, feature, cell_width):
    color={"BUG_BOUNTY":"green","OSINT":"yellow","REVERSE":"pink"}[feature.category]
    label=f"{number:03d}  {feature.name}"
    return ansi(label[:cell_width].ljust(cell_width),color)


def menu():
    width=shutil.get_terminal_size((120,30)).columns
    columns=3 if width>=108 else (2 if width>=74 else 1)
    numbered=_numbered()
    groups=[numbered[i::columns] for i in range(columns)]
    cell=max(24,(width-(columns+1))//columns)
    print(ansi("┌"+"─"*(cell)*columns+"─"*(columns-1)+"┐","blue"))
    titles=["BUG BOUNTY 001-050","OSINT 051-100","REVERSE 101-120"]
    titles=titles[:columns]
    print(ansi("│"+"│".join(title.center(cell) for title in titles)+"│","blue"))
    print(ansi("├"+"┼".join("─"*cell for _ in range(columns))+"┤","blue"))
    for row in range(max(map(len,groups))):
        cells=[_item(*groups[col][row],cell) if row<len(groups[col]) else "".ljust(cell) for col in range(columns)]
        print("│"+"│".join(cells)+"│")
    print(ansi("└"+"┴".join("─"*cell for _ in range(columns))+"┘","blue"))
    print(ansi("Ketik nomor 001-120 atau ID fitur (BB-01/OS-01/RE-01)","white"))
    print(ansi("[R] Recon  [B] Bug Bounty  [O] OSINT  [V] Reverse  [H] Help  [0] Keluar","pink"))
    print(ansi("Status: SAFE MODE aktif • Scope enforcement aktif • Temuan hanya dari evidence aktual","cyan"))


def feature_from_choice(choice: str):
    value=choice.strip().upper()
    if value.isdigit():
        number=int(value)
        return FEATURES[number-1] if 1<=number<=len(FEATURES) else None
    return next((feature for feature in FEATURES if feature.id==value),None)


def feature_summary():
    counts={}
    for f in FEATURES:
        counts.setdefault(f.category,{"total":0,"available":0,"planned":0})
        counts[f.category]["total"]+=1
        counts[f.category]["available"]+=f.status=="AVAILABLE"
        counts[f.category]["planned"]+=f.status=="PLANNED"
    return counts
