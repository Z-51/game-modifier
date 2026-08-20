"""Anti-cheat / online-protection guard.

The tool is intended only for single-player, offline games the user owns.
Attempting to write memory in a title protected by kernel-level anti-cheat is
both against those games' terms and a good way to crash the game or get the
account banned - so if a known anti-cheat is detected the guard refuses by
default (configurable via ``safety.block_anti_cheat``).
"""

from __future__ import annotations

from typing import Iterable

# Substrings matched (case-insensitive) against loaded module names and the
# names of other running processes.
ANTI_CHEAT_SIGNATURES: dict[str, list[str]] = {
    "EasyAntiCheat": ["easyanticheat", "eac_launcher", "easyanticheat_eos"],
    "BattlEye": ["beservice", "beclient", "bedaisy", "battleye"],
    "Riot Vanguard": ["vgc", "vgk", "vanguard"],
    "nProtect GameGuard": ["gameguard", "gamemon", "npggnt", "npgg"],
    "XIGNCODE3": ["xigncode", "x3.xem", "xhunter"],
    "Denuvo Anti-Cheat": ["denuvoanti", "denuvo-anti"],
    "PunkBuster": ["pnkbstr", "punkbuster"],
    "mhyprot (miHoYo)": ["mhyprot"],
    "FACEIT": ["faceit"],
    "FairFight": ["fairfight"],
    "Ricochet (COD)": ["ricochet"],
    "TenSafe/ACE (Tencent)": ["tensafe", "acebase", "acepro", "tss", "tenprotect"],
    "NEACProtect (NetEase)": ["neacprotect", "neac"],
    "HackShield": ["hackshield", "hsupdate"],
    "Anti-Cheat Expert": ["anti-cheat-expert", "anti_cheat_expert"],
    # Deliberately narrow: "steamclient"/"valve" would false-positive on every
    # Steam single-player title; only match explicit VAC enforcement modules.
    "VAC": ["vacmodule"],
}


def detect_anti_cheat(
    module_names: Iterable[str],
    process_names: Iterable[str] = (),
) -> dict:
    """Return a structured detection report.

    ``{"detected": bool, "systems": [...], "hits": [{"system","match","where"}]}``
    """

    hits: list[dict] = []
    systems: set[str] = set()

    def _scan(names: Iterable[str], where: str) -> None:
        for raw in names:
            low = (raw or "").lower()
            if not low:
                continue
            for system, frags in ANTI_CHEAT_SIGNATURES.items():
                for frag in frags:
                    if frag in low:
                        hits.append({"system": system, "match": raw, "where": where})
                        systems.add(system)

    _scan(module_names, "module")
    _scan(process_names, "process")

    return {
        "detected": bool(systems),
        "systems": sorted(systems),
        "hits": hits,
    }
