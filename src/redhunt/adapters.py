from __future__ import annotations

from dataclasses import dataclass
from .core import run_external


@dataclass(frozen=True)
class ExternalAdapter:
    binary: str
    label: str

    def version(self):
        return run_external(self.binary, ["--version"], timeout=10)

    def run_safe(self, args: list[str], timeout=60):
        # Caller must validate scope and arguments before invoking this adapter.
        return run_external(self.binary, args, timeout=timeout)


NmapAdapter = ExternalAdapter("nmap", "Nmap")
NucleiAdapter = ExternalAdapter("nuclei", "Nuclei")
SubfinderAdapter = ExternalAdapter("subfinder", "Subfinder")
AmassAdapter = ExternalAdapter("amass", "Amass")
FFUFAdapter = ExternalAdapter("ffuf", "FFUF")
GobusterAdapter = ExternalAdapter("gobuster", "Gobuster")
MasscanAdapter = ExternalAdapter("masscan", "Masscan")
JadxAdapter = ExternalAdapter("jadx", "Jadx")
ApktoolAdapter = ExternalAdapter("apktool", "Apktool")
Radare2Adapter = ExternalAdapter("radare2", "Radare2")
