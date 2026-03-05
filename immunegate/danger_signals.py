"""
ImmuneGate – Danger Signal Detection
Erkennt gefährliche Muster in Text via Regex.
"""

import re
from .schemas import DangerSignal

# ─── SIGNAL PATTERNS ──────────────────────────────────────────────────────────

PATTERNS: dict[DangerSignal, list[str]] = {
    DangerSignal.INJ_OVERRIDE: [
        r"ignore\s+(previous|all|prior)\s+instructions",
        r"system\s+prompt",
        r"forget\s+(everything|all|what)",
        r"new\s+instructions",
        r"override\s+(your|the)\s+(instructions|rules|policy)",
        r"disregard\s+(previous|all)",
        r"you\s+are\s+now",
    ],
    DangerSignal.EXFILTRATION: [
        r"send\s+to\s+\S+@\S+",
        r"upload\s+to\s+(http|https|ftp)",
        r"paste\s+(here|this|the\s+content)",
        r"copy\s+(and\s+)?send",
        r"forward\s+(all|this|the\s+file)",
        r"exfiltrat",
        r"transfer\s+(all\s+)?(files|data|content)",
    ],
    DangerSignal.CREDENTIALS: [
        r"\bpassword\b",
        r"\bpasswort\b",
        r"\bapi[_\s]?key\b",
        r"\btoken\b",
        r"\bsecret\b",
        r"\bcredential",
        r"\bprivate[_\s]?key\b",
        r"\bauth[_\s]?(token|key|code)\b",
        r"\bssh[_\s]?key\b",
    ],
    DangerSignal.MASS_DESTRUCT: [
        r"delete\s+all",
        r"l(ö|oe)sch\s+alles",
        r"remove\s+all",
        r"wipe\s+(out\s+)?(all|everything|the\s+disk)",
        r"rm\s+-rf",
        r"format\s+(the\s+)?(disk|drive|partition)",
        r"purge\s+all",
        r"erase\s+(all|everything)",
        r"destroy\s+(all|everything|the\s+data)",
    ],
    DangerSignal.STEALTH: [
        r"don['\u2019]?t\s+(tell|inform|notify|show|let)\s+(the\s+)?user",
        r"without\s+(notif|inform|telling|asking)",
        r"silently",
        r"in\s+the\s+background",
        r"ohne\s+(den\s+)?(nutzer|user)\s+zu\s+(inform|benachricht)",
        r"hide\s+(this|it|the\s+action)",
        r"do\s+not\s+(inform|notify|tell)\s+(the\s+)?user",
    ],
}

# ─── DETECTION FUNCTION ───────────────────────────────────────────────────────

def detect_danger_signals(text: str) -> list[DangerSignal]:
    """
    Durchsucht Text nach Danger Signals.
    Gibt Liste der erkannten Signale zurück.
    """
    if not text:
        return []

    found = []
    text_lower = text.lower()

    for signal, patterns in PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, text_lower, re.IGNORECASE):
                found.append(signal)
                break  # Pro Signal nur einmal zählen

    return found
