"""
ImmuneGate Plugin – No Sunday Deletes

DELETE-Aktionen am Sonntag lösen ein ASK aus und erfordern damit
menschliche Bestätigung. Ideal für Produktionsumgebungen, bei denen
am Wochenende kein Support-Team erreichbar ist.

Verhalten:
    Sonntag  + DELETE → ASK  (zusätzliche Bestätigung nötig)
    Alle anderen Tage →  None (Plugin enthält sich)

Registrierte Rule-ID: PLUGIN-NO-SUNDAY-DELETE
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from immunegate.plugins import BasePlugin
from immunegate.policy_engine import PolicyMatch
from immunegate.schemas import Action, Verb, Decision


class NoSundayDeletesPlugin(BasePlugin):
    """
    Schutzmechanismus für Produktionssysteme ohne Wochenend-Support.

    Gibt ASK zurück wenn:
        - action.verb == Verb.DELETE
        - Wochentag == Sonntag (datetime.weekday() == 6)

    Beachte: Core-Regeln wie TOL-002 (Sandbox ALLOW) haben durch die
    globale DENY > ALLOW > ASK Precedence immer das letzte Wort –
    das Plugin ergänzt die Entscheidung, überschreibt sie nicht.
    """

    @property
    def plugin_id(self) -> str:
        return "PLUGIN-NO-SUNDAY-DELETE"

    def evaluate(self, action: Action) -> Optional[PolicyMatch]:
        if action.verb == Verb.DELETE and datetime.now().weekday() == 6:
            return PolicyMatch(
                rule_id  = "PLUGIN-NO-SUNDAY-DELETE",
                decision = Decision.ASK,
                reason   = (
                    "Löschaktion am Sonntag – kein Support verfügbar. "
                    "Menschliche Bestätigung erforderlich (Plugin)."
                ),
            )
        return None
