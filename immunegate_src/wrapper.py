"""
ImmuneGate – Tool Wrapper
Der Einzeiler der jeden Agenten schützt: gate.wrap(agent)

Verwendung:
    from immunegate import ImmunGate
    ig = ImmuneGate()
    ig.files.delete("/projects/")       # → Gate evaluiert automatisch
    ig.email.send("user@extern.com", "Hallo", body="...")
    ig.web.browse("https://example.com")
"""

import hashlib
from .schemas import Action, Verb, Tool, Destination, SourceTrust, Decision
from .danger_signals import detect_danger_signals
from .audit import AuditLog
from .gate import PermissionGate


class ImmuneGate:
    """
    Hauptklasse für Agenten-Integration.
    
    Beispiel:
        ig = ImmuneGate()
        ig.files.delete("/projects/report.pdf")
        ig.email.send("extern@gmail.com", "Subject", body="...")
        ig.web.browse("https://attacker.com")
    """

    def __init__(self, session_id: str = None, auto_deny_ask: bool = False):
        """
        auto_deny_ask: True = bei ASK automatisch DENY (non-interactive Modus)
        """
        self.audit          = AuditLog(session_id)
        self.gate           = PermissionGate(self.audit)
        self.auto_deny_ask  = auto_deny_ask
        self._contaminated  = False  # Contamination Tag für Source Lineage

        # Sub-wrappers
        self.files = _FilesWrapper(self)
        self.email = _EmailWrapper(self)
        self.web   = _WebWrapper(self)

    def receive_input(self, content: str, source_trust: SourceTrust) -> str:
        """
        Registriert einen externen Input.
        Setzt Contamination Tag wenn untrusted.
        Gibt input_id zurück für Source Lineage.
        """
        danger_signals = detect_danger_signals(content)
        content_hash   = hashlib.sha256(content.encode()).hexdigest()[:16]

        self.audit.log_input_received(
            source_kind    = source_trust.value,
            trust_modifier = 0,
            danger_signals = [s.value for s in danger_signals],
            content_hash   = content_hash,
        )

        # Contamination: wenn untrusted → Session markieren
        if source_trust in {SourceTrust.WEB, SourceTrust.EMAIL_EXTERNAL}:
            self._contaminated = True

        return content_hash

    def _execute(self, action: Action) -> bool:
        """
        Zentrale Execute-Methode.
        Gibt True zurück wenn Aktion ausgeführt wurde.
        """
        # Contamination Tag übertragen
        action.contaminated = self._contaminated
        action.session_id   = self.audit.session_id

        # Gate evaluieren
        result = self.gate.evaluate(action)

        # Entscheidung anzeigen
        self._print_gate_result(result)

        if result.decision == Decision.ALLOW:
            self.audit.log_tool_call(
                action.action_id, action.tool.value,
                f"Ausgeführt: {action.verb.value} → {action.target}", True
            )
            return True

        elif result.decision == Decision.ASK:
            self.audit.log_gate_prompt(action.action_id, result.preview or {})

            if self.auto_deny_ask:
                print("  [Auto-DENY da non-interactive Modus]")
                self.audit.log_human_decision(action.action_id, "auto_deny")
                return False

            # Interaktive Bestätigung
            approved = self._ask_human(result)
            choice   = "approve" if approved else "deny"
            self.audit.log_human_decision(action.action_id, choice)

            if approved:
                self.audit.log_tool_call(
                    action.action_id, action.tool.value,
                    f"Ausgeführt nach Bestätigung: {action.verb.value} → {action.target}", True
                )
            return approved

        else:  # DENY
            self.audit.log_tool_call(
                action.action_id, action.tool.value,
                f"GEBLOCKT: {action.verb.value} → {action.target}", False
            )
            return False

    def _print_gate_result(self, result):
        icons = {Decision.ALLOW: "✅", Decision.ASK: "⚠️ ", Decision.DENY: "🛑"}
        icon  = icons[result.decision]
        print(f"\n{icon} GATE [{result.decision.value}] {result.action.verb.value.upper()} → {result.action.target or '(kein Ziel)'}")
        print(f"   Risk Score: {result.risk_score}/100  |  Rules: {', '.join(result.matched_rule_ids)}")
        for i, reason in enumerate(result.reasons, 1):
            print(f"   Grund {i}: {reason}")

    def _ask_human(self, result) -> bool:
        print(f"\n  📋 PREVIEW:")
        if result.preview:
            for k, v in result.preview.items():
                print(f"     {k}: {v}")
        response = input("\n  → Aktion genehmigen? [j/n]: ").strip().lower()
        return response in {"j", "ja", "y", "yes"}

    def export_audit(self, filepath: str = "immunegate_audit.json"):
        self.audit.export_json(filepath)

    def print_summary(self):
        self.audit.print_summary()


# ─── SUB-WRAPPERS ─────────────────────────────────────────────────────────────

class _FilesWrapper:
    def __init__(self, ig: ImmuneGate):
        self._ig = ig

    def read(self, path: str) -> bool:
        return self._ig._execute(Action(
            verb=Verb.READ, tool=Tool.FILES,
            destination=Destination.INTERNAL, target=path,
            source_trust=SourceTrust.INTERNAL_SYSTEM,
        ))

    def write(self, path: str, content: str = "", sensitive: bool = False) -> bool:
        verb = Verb.WRITE_SENSITIVE if sensitive else Verb.WRITE
        ds   = detect_danger_signals(content)
        return self._ig._execute(Action(
            verb=verb, tool=Tool.FILES,
            destination=Destination.INTERNAL, target=path,
            content=content, danger_signals=ds,
            source_trust=self._ig._get_current_source_trust(),
        ))

    def delete(self, path: str) -> bool:
        # Danger Signals im Pfad prüfen
        ds = detect_danger_signals(path)
        return self._ig._execute(Action(
            verb=Verb.DELETE, tool=Tool.FILES,
            destination=Destination.INTERNAL, target=path,
            danger_signals=ds,
            source_trust=self._ig._get_current_source_trust(),
        ))


class _EmailWrapper:
    def __init__(self, ig: ImmuneGate):
        self._ig = ig

    def send(self, recipient: str, subject: str, body: str = "") -> bool:
        domain      = recipient.split("@")[-1] if "@" in recipient else recipient
        destination = (Destination.INTERNAL
                       if domain in {"company.com", "intern.local"}
                       else Destination.EXTERNAL)
        ds = detect_danger_signals(f"{subject} {body}")
        return self._ig._execute(Action(
            verb=Verb.SEND, tool=Tool.EMAIL,
            destination=destination, target=recipient,
            content=f"Subject: {subject}\n\n{body}",
            danger_signals=ds,
            source_trust=self._ig._get_current_source_trust(),
        ))


class _WebWrapper:
    def __init__(self, ig: ImmuneGate):
        self._ig = ig

    def browse(self, url: str) -> bool:
        return self._ig._execute(Action(
            verb=Verb.BROWSE, tool=Tool.WEB,
            destination=Destination.EXTERNAL, target=url,
            source_trust=SourceTrust.USER_DIRECT,
        ))

    def receive_content(self, url: str, content: str) -> str:
        """Web-Inhalt empfangen und als untrusted registrieren."""
        return self._ig.receive_input(content, SourceTrust.WEB)


# ─── HELPER ───────────────────────────────────────────────────────────────────

def _get_current_source_trust(self) -> SourceTrust:
    """Gibt aktuelle Source Trust zurück (kontaminiert = web-level)."""
    if self._contaminated:
        return SourceTrust.WEB
    return SourceTrust.USER_DIRECT

# Monkey-patch auf ImmuneGate
ImmuneGate._get_current_source_trust = _get_current_source_trust

# Import shortcut
from .danger_signals import detect_danger_signals
