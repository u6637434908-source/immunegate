"""
ImmuneGate – Danger Signal Detection
Erkennt gefährliche Muster in Text via Regex.

Sprachunterstützung:
  INJ_OVERRIDE  → EN · DE · FR · ES
  EXFILTRATION  → EN · DE
  CREDENTIALS   → EN · DE · FR · ES
  MASS_DESTRUCT → EN · DE
  STEALTH       → EN · DE
"""

import re
from .schemas import DangerSignal

# ─── SIGNAL PATTERNS ──────────────────────────────────────────────────────────

PATTERNS: dict[DangerSignal, list[str]] = {

    # ── INJ_OVERRIDE ────────────────────────────────────────────────────────
    # Versuche, dem Agenten neue Anweisungen unterzuschieben oder seine
    # bestehenden Regeln zu überschreiben.
    DangerSignal.INJ_OVERRIDE: [
        # ── English ──
        r"ignore\s+(previous|all|prior|your)\s+instructions",
        r"disregard\s+(previous|all|prior|your)\s+(instructions?|rules?|guidelines?)",
        r"forget\s+(everything|all|what\s+you|your\s+previous)",
        r"(new|updated|revised|changed)\s+instructions?",
        r"override\s+(your|the|all)\s+(instructions?|rules?|policy|guidelines?)",
        r"your\s+(new|updated|real|actual|true)\s+(instructions?|rules?|purpose|goal|task)",
        r"you\s+are\s+now\s+(a|an|the)\b",
        r"act\s+as\s+(if\s+you\s+(were?|are)|a|an)\b",
        r"pretend\s+(you\s+are|to\s+be|that)",
        r"system\s+prompt",
        r"DAN\s+mode",
        r"jailbreak",
        r"developer\s+mode",
        r"from\s+now\s+on\s+(you\s+are|ignore|forget)",

        # ── Deutsch ──
        r"ignorier[et]?\s+(alle?\s+)?(vorherigen?|bisherigen?)\s+(Anweisungen?|Regeln?|Befehle?|Vorgaben?)",
        r"vergiss\s+(alles|alle\s+(vorherigen?|bisherigen?)\s+(Anweisungen?|Regeln?))",
        r"(neue|aktualisierte?|ge[aä]nderte?)\s+Anweisungen?",
        r"überschreib[et]?\s+(die\s+)?(Regeln?|Anweisungen?|Vorgaben?)",
        r"du\s+bist\s+jetzt\s+(ein|eine|der|die|das)\b",
        r"tu\s+(so\s+als\s+ob|als\s+wärst)\s+du",
        r"ab\s+jetzt\s+(bist\s+du|ignorierst\s+du|vergisst\s+du)",
        r"deine\s+(neuen?|wahren?|eigentlichen?)\s+Anweisungen?\s+(lauten|sind|sagen)",
        r"system\s*[-–]?\s*(prompt|anweisung)",
        r"Jailbreak",

        # ── Français ──
        r"ignor(?:e|er|ez)\s+(les\s+)?(instructions?|règles?)\s+(précédentes?|antérieures?)",
        r"oubli[ez]\s+(tout|toutes?\s+les\s+instructions?|vos?\s+instructions?)",
        r"(nouvelles?|mises?\s+à\s+jour)\s+instructions?",
        r"tu\s+es\s+maintenant\s+(un|une|le|la)\b",
        r"vous\s+êtes\s+maintenant\s+(un|une|le|la)\b",
        r"à\s+partir\s+de\s+maintenant\s+(tu|vous)\s+(es|êtes|ignores?|oubli)",

        # ── Español ──
        r"ignora[r]?\s+(las?\s+)?(instrucciones?|reglas?)\s+anteriores?",
        r"olvida[r]?\s+(todo|las?\s+instrucciones?|tus?\s+reglas?)",
        r"(nuevas?|actualizadas?)\s+instrucciones?",
        r"ahora\s+(eres?|actúas?\s+como|serás?)\b",
        r"a\s+partir\s+de\s+ahora\s+(eres?|ignora|olvida)",
        r"actúa\s+como\s+(si\s+fueras?|un|una)\b",
    ],

    # ── EXFILTRATION ─────────────────────────────────────────────────────────
    # Versuche, Daten nach außen zu schaffen.
    DangerSignal.EXFILTRATION: [
        # ── English ──
        r"send\s+(all\s+)?(files?|data|content|documents?|this)\s+to\s+\S+@\S+",
        r"send\s+to\s+\S+@\S+",
        r"upload\s+to\s+(http|https|ftp|sftp)",
        r"upload\s+(all\s+)?(files?|data|content)\s+to\s+(http|https|ftp|sftp)",
        r"paste\s+(here|this|all|the\s+content|it)",
        r"copy\s+(and\s+)?send\s+(to|this)",
        r"forward\s+(all|this|every|the\s+(file|data|content))",
        r"exfiltrat",
        r"transfer\s+(all\s+)?(files?|data|content|documents?)",
        r"leak\s+(the\s+)?(files?|data|content|documents?|secrets?)",
        r"extract\s+(and\s+)?(send|forward|transmit)\s+(the\s+)?(data|files?|content)",
        r"smuggl(e|ing)\s+(out|data|files?)",

        # ── Deutsch ──
        r"schick[et]?\s+(alle[sr]?|die)\s+(Dateien?|Daten|Dokumente?)\s+an\b",
        r"schick[et]?\s+(es|alles)\s+an\s+\S+@\S+",
        r"lade\s+(alle?\s+)?(Dateien?|Daten)?\s+(hoch|rauf)\s+(auf|zu|nach)\s+(http|https|ftp)",
        r"leite\s+(alle[sr]?|die)\s+(Dateien?|Daten)\s+(weiter|ab)\s+(an|zu)",
        r"exportier[et]?\s+(alle[sr]?|die)\s+(Daten|Dateien|Dokumente?)",
        r"übertrag[et]?\s+(alle[sr]?|die)\s+(Daten|Dateien)\s+(an|zu|nach)",
        r"führ[et]?\s+(die\s+)?(Daten|Dateien)\s+ab",
    ],

    # ── CREDENTIALS ──────────────────────────────────────────────────────────
    # Anweisungen, Zugangsdaten oder Schlüssel preiszugeben.
    DangerSignal.CREDENTIALS: [
        # ── English ──
        r"\bpassword\b",
        r"\bpassphrase\b",
        r"\bapi[_\s\-]?key\b",
        r"\bapi[_\s\-]?token\b",
        r"\baccess[_\s\-]?token\b",
        r"\bbearer[_\s\-]?token\b",
        r"\bauth[_\s\-]?(token|key|code|secret)\b",
        r"\bprivate[_\s\-]?key\b",
        r"\bsecret[_\s\-]?(key|token|code)?\b",
        r"\bcredential",
        r"\bssh[_\s\-]?key\b",
        r"\b(client|app)[_\s\-]?secret\b",
        r"\brefresh[_\s\-]?token\b",
        r"\bsigning[_\s\-]?(key|secret)\b",
        r"\bencryption[_\s\-]?key\b",
        r"\b\.env\b",
        r"\bservice[_\s\-]?account\b",

        # ── Deutsch ──
        r"\bPasswort\b",
        r"\bpasswort\b",
        r"\bKennwort\b",
        r"\bKennworte?\b",
        r"\bZugangsdaten?\b",
        r"\bZugangscode\b",
        r"\bAnmeldedaten?\b",
        r"\bAPI[_\s\-]?Schlüssel\b",
        r"\bGeheimschlüssel\b",
        r"\bPrivatschlüssel\b",
        r"\bZertifikat[_\s\-]?schlüssel\b",
        r"\bVerschlüsselungsschlüssel\b",

        # ── Français ──
        r"\bmot\s+de\s+passe\b",
        r"\bcl[eé]\s+(API|secrète?|privée?|d['']authentification)\b",
        r"\bjeton\s+d['']acc[eè]s\b",
        r"\bjeton\s+(API|secret|d['']authentification)\b",
        r"\bidentifiant[s]?\b",
        r"\bcode\s+secret\b",
        r"\bclé\s+de\s+chiffrement\b",

        # ── Español ──
        r"\bcontraseña\b",
        r"\bclave\s+(API|secreta?|privada?|de\s+cifrado)\b",
        r"\bcredenciales?\b",
        r"\btoken\s+(de\s+acceso|secreto|de\s+autenticaci[oó]n)\b",
        r"\bllaves?\s+(privadas?|secretas?|de\s+API)\b",
    ],

    # ── MASS_DESTRUCT ─────────────────────────────────────────────────────────
    # Anweisungen, die auf massenhafte oder irreversible Datenzerstörung zielen.
    DangerSignal.MASS_DESTRUCT: [
        # ── English ──
        r"delete\s+all",
        r"remove\s+all",
        r"wipe\s+(out\s+)?(all|everything|the\s+disk|the\s+drive|the\s+server)",
        r"rm\s+-rf",
        r"format\s+(the\s+)?(disk|drive|partition|volume|filesystem)",
        r"purge\s+all",
        r"erase\s+(all|everything|the\s+(disk|drive|data|files?))",
        r"destroy\s+(all|everything|the\s+data|the\s+files?|the\s+server)",
        r"nuke\s+(the\s+)?(database|server|disk|files?|everything)",
        r"drop\s+(database|table|schema|all\s+tables)",
        r"truncate\s+(all|the\s+)?(tables?|database)",
        r"shred\s+(all|the\s+)?(files?|data|documents?)",
        r"overwrite\s+(all|every)\s+(files?|data|records?)",
        r"mass\s+(delete|removal|destruction|wipe)",

        # ── Deutsch ──
        r"l[öo]sch[et]?\s+(alles|alle[sr]?|die\s+gesamten?)\s+(Dateien?|Daten|Projekte?|Records?)",
        r"l[öo]sch[et]?\s+alles",
        r"alle\s+Daten\s+(l[öo]schen|entfernen|vernichten|löschen)",
        r"alles\s+l[öo]schen",
        r"entfern[et]?\s+alles",
        r"wisch[et]?\s+(alles|alle[sr]?|die\s+Festplatte)\s*(aus|weg|leer)?",
        r"formatier[et]?\s+(die\s+)?(Festplatte|Disk|Partition|Laufwerk)",
        r"vernicht[et]?\s+(alle[sr]?|die)\s+(Daten|Dateien|Dokumente?)",
        r"lösch[et]?\s+(den\s+)?(gesamten?\s+)?(Inhalt|Datenbank|Datei)",
        r"DROP\s+(TABLE|DATABASE|SCHEMA)",
    ],

    # ── STEALTH ───────────────────────────────────────────────────────────────
    # Versuche, Aktionen vor dem Nutzer zu verbergen oder Logs zu umgehen.
    DangerSignal.STEALTH: [
        # ── English ──
        r"don[''\u2019]?t\s+(tell|inform|notify|show|let|alert)\s+(the\s+)?user",
        r"do\s+not\s+(inform|notify|tell|show|alert)\s+(the\s+)?user",
        r"without\s+(notif|inform|telling|asking|alerting|the\s+user\s+know)",
        r"without\s+(the\s+)?user\s+(knowing|noticing|being\s+aware)",
        r"silently",
        r"in\s+the\s+background",
        r"hide\s+(this|it|the\s+(action|operation|request|command))",
        r"covertly",
        r"secretly",
        r"under\s+the\s+radar",
        r"without\s+log(ging)?",
        r"bypass\s+(the\s+)?(log|audit|monitor|detection|security)",
        r"avoid\s+(detection|logging|monitoring|audit)",
        r"don[''\u2019]?t\s+log\s+(this|it|the\s+action)",
        r"leave\s+no\s+(trace|log|record)",

        # ── Deutsch ──
        r"ohne\s+(den\s+)?(Nutzer|User|Benutzer)\s+zu\s+(inform|benachricht|sag|zeig)",
        r"ohne\s+(Benachrichtigung|Meldung|Protokoll|Log)",
        r"im\s+Hintergrund\s+(ausführen|laufen|erledigen)",
        r"unbemerkt",
        r"heimlich",
        r"ohne\s+es\s+zu\s+(melden|protokollieren|loggen|zeigen)",
        r"versteckt[e]?\s+(Aktion|Ausführung|Operation)",
        r"sag\s+(es\s+)?dem\s+(Nutzer|Benutzer)\s+nicht",
        r"nicht\s+(protokollieren|loggen|aufzeichnen|melden)",
        r"kein[e]?\s+(Log|Protokoll|Aufzeichnung|Spur)\s+(hinterlassen|erstellen)",
        r"umgeh[et]?\s+(die\s+)?(Protokollierung|Aufzeichnung|Überwachung|Sicherheit)",
    ],
}

# ─── DETECTION FUNCTION ───────────────────────────────────────────────────────

def detect_danger_signals(text: str) -> list[DangerSignal]:
    """
    Durchsucht Text nach Danger Signals.
    Gibt Liste der erkannten Signale zurück (jedes Signal max. einmal).
    Unterstützt: EN · DE · FR (INJ_OVERRIDE, CREDENTIALS) · ES (INJ_OVERRIDE, CREDENTIALS)
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
