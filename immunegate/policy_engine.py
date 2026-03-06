"""
ImmuneGate – Policy Engine
Evaluiert Policy-Regeln mit Precedence: DENY > ALLOW > ASK > Score Fallback.
"""

from dataclasses import dataclass
from typing import Optional, TYPE_CHECKING
from .schemas import Action, Decision, Verb, Destination, SourceTrust, DangerSignal, Sensitivity

if TYPE_CHECKING:
    from .config import ImmuneGateConfig

UNTRUSTED_SOURCES = {SourceTrust.WEB, SourceTrust.EMAIL_EXTERNAL}

# Defaults – werden durch Config überschrieben
_DEFAULT_ALLOWLIST     = {"company.com", "intern.local", "localhost"}
_DEFAULT_SANDBOX_PATHS = ["/tmp/demo_sandbox/", "/tmp/test/"]


# ─── POLICY RULE ──────────────────────────────────────────────────────────────

@dataclass
class PolicyMatch:
    rule_id:  str
    decision: Decision
    reason:   str


# ─── RULE EVALUATION ──────────────────────────────────────────────────────────

def _get_recipient_domain(target: str) -> str:
    if "@" in target:
        return target.split("@")[-1].lower()
    return target.lower()


def evaluate_policies(action: Action, config=None) -> list[PolicyMatch]:
    """
    Evaluiert alle Regeln und gibt Matches zurück.
    Caller wendet Precedence an: DENY > ALLOW > ASK
    """
    # Config-Werte oder Defaults
    internal_allowlist = set(config.internal_domains) if config else _DEFAULT_ALLOWLIST
    sandbox_paths      = config.sandbox_paths if config else _DEFAULT_SANDBOX_PATHS

    matches = []

    # ── PRR: Primär-Reflexregeln (angeboren, sicherheitskritisch) ─────────────

    # PRR-001: Credentials nach extern → immer DENY
    if (action.verb in {Verb.SEND, Verb.UPLOAD}
            and action.destination == Destination.EXTERNAL
            and DangerSignal.CREDENTIALS in action.danger_signals):
        matches.append(PolicyMatch("PRR-001", Decision.DENY,
            "Credentials-Exfiltration nach extern ist absolut verboten"))

    # PRR-002: Delete → immer ASK (außer PRR-007 überschreibt)
    if action.verb == Verb.DELETE:
        matches.append(PolicyMatch("PRR-002", Decision.ASK,
            "Jede Löschaktion erfordert menschliche Bestätigung"))

    # PRR-003: Send external aus untrusted Source → DENY
    if (action.verb == Verb.SEND
            and action.destination == Destination.EXTERNAL
            and action.source_trust in UNTRUSTED_SOURCES):
        matches.append(PolicyMatch("PRR-003", Decision.DENY,
            "Untrusted Source darf keine externe Kommunikation triggern"))

    # PRR-004: Write bei untrusted Einfluss → ASK
    if (action.verb in {Verb.WRITE, Verb.WRITE_SENSITIVE}
            and action.source_trust in UNTRUSTED_SOURCES):
        matches.append(PolicyMatch("PRR-004", Decision.ASK,
            "Schreibzugriff unter Fremdeinfluss erfordert Bestätigung"))

    # PRR-004b: Contamination Tag (MVP Source Lineage)
    if (action.contaminated
            and action.verb in {Verb.WRITE, Verb.WRITE_SENSITIVE, Verb.DELETE, Verb.SEND, Verb.UPLOAD}
            and action.source_trust not in UNTRUSTED_SOURCES):
        matches.append(PolicyMatch("PRR-004", Decision.ASK,
            "Session ist durch untrusted Input kontaminiert"))

    # PRR-005: Read / Browse → ALLOW
    if action.verb in {Verb.READ, Verb.BROWSE}:
        matches.append(PolicyMatch("PRR-005", Decision.ALLOW,
            "Lesen und Browsen ist risikoarm"))

    # PRR-006: Read Sensitive → ASK
    if action.verb == Verb.READ_SENSITIVE:
        matches.append(PolicyMatch("PRR-006", Decision.ASK,
            "Sensible Daten lesen erfordert Bewusstsein"))

    # PRR-007: MASS_DESTRUCT → sofort DENY
    if DangerSignal.MASS_DESTRUCT in action.danger_signals:
        matches.append(PolicyMatch("PRR-007", Decision.DENY,
            "MASS_DESTRUCT-Signal erkannt – sofortiger Reflex-DENY"))

    # PRR-008: STEALTH → sofort DENY
    if DangerSignal.STEALTH in action.danger_signals:
        matches.append(PolicyMatch("PRR-008", Decision.DENY,
            "STEALTH-Signal erkannt – versteckte Aktionen sind verboten"))

    # ── TOL: Toleranzregeln (Kontext-Ausnahmen) ───────────────────────────────

    # TOL-001: Send internal auf Allowlist → ALLOW
    if (action.verb == Verb.SEND
            and action.destination == Destination.INTERNAL
            and _get_recipient_domain(action.target) in internal_allowlist):
        matches.append(PolicyMatch("TOL-001", Decision.ALLOW,
            "Interne Kommunikation auf Allowlist ist erlaubt"))

    # TOL-002: Delete in Sandbox → ALLOW
    if (action.verb == Verb.DELETE
            and any(action.target.startswith(p) for p in sandbox_paths)):
        matches.append(PolicyMatch("TOL-002", Decision.ALLOW,
            "Delete in Sandbox-Bereich ist erlaubt"))

    # TOL-003: Send external an neue Domain → ASK
    if (action.verb == Verb.SEND
            and action.destination == Destination.EXTERNAL
            and _get_recipient_domain(action.target) not in internal_allowlist
            and action.source_trust == SourceTrust.USER_DIRECT):
        matches.append(PolicyMatch("TOL-003", Decision.ASK,
            "Neue externe Empfänger müssen bestätigt werden"))

    # ── OBS: Observationsregeln (Tagging) ─────────────────────────────────────
    # OBS-001 wird im Tool Wrapper / Context Engine gesetzt, nicht hier

    return matches


def apply_precedence(matches: list[PolicyMatch]) -> Optional[PolicyMatch]:
    """
    Wendet Precedence an: DENY > ALLOW > ASK
    Gibt die höchste Priorität zurück.
    """
    if not matches:
        return None

    for decision in [Decision.DENY, Decision.ALLOW, Decision.ASK]:
        for match in matches:
            if match.decision == decision:
                return match

    return matches[0]
