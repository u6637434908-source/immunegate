"""
ImmuneGate Plugin – Hallertau Regional Allowlist

Lokale Bayerische Domains (Hallertau-Region) werden für ausgehende
Kommunikation explizit erlaubt. Hintergrund: Diese Betriebe sind bekannte
Geschäftspartner der Region, die nicht in der globalen Core-Allowlist stehen.

Verhalten:
    send + EXTERNAL + Domain in HALLERTAU_DOMAINS → ALLOW
    Alle anderen Aktionen                          → None (Plugin enthält sich)

Durch das ALLOW kann TOL-003 (neue externe Empfänger → ASK) überschrieben
werden – der Nutzer muss diese Domains nicht einzeln bestätigen.

Registrierte Rule-ID: PLUGIN-HALLERTAU-ALLOWLIST
"""

from __future__ import annotations

from typing import Optional

from immunegate.plugins import BasePlugin
from immunegate.policy_engine import PolicyMatch
from immunegate.schemas import Action, Verb, Destination, Decision


# Bekannte regionale Partner – nach Bedarf erweiterbar
HALLERTAU_DOMAINS: set = {
    "reiterhof-ried.de",
    "sd-tuning.de",
    "brauerei-karg.de",
    "hopfenland.de",
    "hallertau.net",
    "gemeindewald-wolnzach.de",
}


class HallertauAllowlistPlugin(BasePlugin):
    """
    Erlaubt ausgehende E-Mails an bekannte Hallertau-Region Domains.

    Gibt ALLOW zurück wenn:
        - action.verb == Verb.SEND
        - action.destination == Destination.EXTERNAL
        - Empfänger-Domain in HALLERTAU_DOMAINS

    Achtung: Core-DENY (z. B. PRR-003 bei WEB-Source) hat immer Vorrang –
    das Plugin kann keine sicherheitskritischen DENY-Entscheidungen aufheben.
    """

    @property
    def plugin_id(self) -> str:
        return "PLUGIN-HALLERTAU-ALLOWLIST"

    def evaluate(self, action: Action) -> Optional[PolicyMatch]:
        if action.verb != Verb.SEND or action.destination != Destination.EXTERNAL:
            return None

        domain = (
            action.target.split("@")[-1].lower()
            if "@" in action.target
            else action.target.lower()
        )

        if domain in HALLERTAU_DOMAINS:
            return PolicyMatch(
                rule_id  = "PLUGIN-HALLERTAU-ALLOWLIST",
                decision = Decision.ALLOW,
                reason   = f"Domain {domain!r} auf Hallertau-Regionalliste (Plugin)",
            )

        return None
