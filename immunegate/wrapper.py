"""
ImmuneGate – Tool Wrapper
Der Einzeiler der jeden Agenten schützt: gate.wrap(agent)

Verwendung:
    from immunegate import ImmuneGate
    ig = ImmuneGate()
    ig.files.delete("/projects/")       # → Gate evaluiert automatisch
    ig.email.send("user@extern.com", "Hallo", body="...")
    ig.web.browse("https://example.com")

Async-Verwendung:
    await ig.files.delete_async("/projects/")
    await ig.email.send_async("user@extern.com", "Hallo", body="...")
"""

from __future__ import annotations

import hashlib
import logging
from typing import List, Optional, Union

from .schemas import Action, Verb, Tool, Destination, SourceTrust, Decision, GateResult
from .danger_signals import detect_danger_signals
from .audit import AuditLog
from .gate import PermissionGate
from .config import load_config, ImmuneGateConfig
from .interceptor import (ImmuneGateInterceptor,
                           _intercept_delete, _intercept_write,
                           _intercept_send, _intercept_browse,
                           _intercept_execute, _intercept_ftp_upload,
                           _intercept_ssh_exec)

logger = logging.getLogger("immunegate")


class ImmuneGate:
    """
    Hauptklasse für Agenten-Integration.

    Beispiel (sync):
        ig = ImmuneGate()
        ig.files.delete("/projects/report.pdf")
        ig.email.send("extern@gmail.com", "Subject", body="...")

    Beispiel (async):
        ig = ImmuneGate(auto_deny_ask=True)
        result = await ig.files.delete_async("/projects/report.pdf")
    """

    def __init__(
        self,
        session_id: Optional[str] = None,
        auto_deny_ask: bool = False,
        config: Optional[Union[str, ImmuneGateConfig]] = None,
        plugins: Optional[Union[str, List]] = None,
    ) -> None:
        """
        session_id:    Überschreibt Config session_id wenn angegeben
        auto_deny_ask: True = bei ASK automatisch DENY (non-interactive Modus)
        config:        Pfad zur YAML-Config (str) oder ImmuneGateConfig-Objekt
        plugins:       Pfad zum Plugin-Verzeichnis (str) oder Liste von
                       BasePlugin-Instanzen. None = keine Plugins.
                       Beispiel: plugins="plugins/"
        """
        # Config laden
        if isinstance(config, ImmuneGateConfig):
            self.config = config
        else:
            self.config = load_config(config)  # config ist Pfad oder None

        # Session ID: Parameter > Config > Default
        effective_session = session_id or self.config.session_id

        if self.config.customer_name:
            logger.info(
                "Kunde: %s | Policy: %s",
                self.config.customer_name,
                self.config.policy_version,
            )
            logger.info("Domains: %s", ", ".join(self.config.internal_domains))

        # Plugins laden
        from .plugins import BasePlugin, load_plugins
        if isinstance(plugins, str):
            loaded_plugins = load_plugins(plugins)
            if loaded_plugins:
                logger.info(
                    "Plugins geladen: %d (%s)",
                    len(loaded_plugins),
                    ", ".join(p.plugin_id for p in loaded_plugins),
                )
        elif isinstance(plugins, list):
            loaded_plugins = [p for p in plugins if isinstance(p, BasePlugin)]
        else:
            loaded_plugins = []

        self.audit         = AuditLog(effective_session)
        self.gate          = PermissionGate(self.audit, config=self.config,
                                            plugins=loaded_plugins)
        self.auto_deny_ask = auto_deny_ask
        self._contaminated = False
        self._interceptor  = ImmuneGateInterceptor(self)

        # Intercept-Methoden auf self patchen
        self._intercept_delete     = lambda path:         _intercept_delete(self, path)
        self._intercept_write      = lambda path, c="":   _intercept_write(self, path, c)
        self._intercept_send       = lambda rec, c="":    _intercept_send(self, rec, c)
        self._intercept_browse     = lambda url:          _intercept_browse(self, url)
        self._intercept_execute    = lambda cmd:          _intercept_execute(self, cmd)
        self._intercept_ftp_upload = lambda srv, pth:     _intercept_ftp_upload(self, srv, pth)
        self._intercept_ssh_exec   = lambda cmd, host:    _intercept_ssh_exec(self, cmd, host)

        # Sub-Wrappers
        self.files = _FilesWrapper(self)
        self.email = _EmailWrapper(self)
        self.web   = _WebWrapper(self)
        self.shell = _ShellWrapper(self)   # Sprint 12
        self.ftp   = _FtpWrapper(self)     # Sprint 12
        self.ssh   = _SshWrapper(self)     # Sprint 12

    def activate(self) -> None:
        """
        Aktiviert den Interceptor Layer.
        Ab jetzt können os.remove, smtplib etc. das Gate nicht mehr umgehen.
        """
        self._interceptor.activate()

    def deactivate(self) -> None:
        """
        Deaktiviert den Interceptor Layer.
        Originalfunktionen werden wiederhergestellt.
        """
        self._interceptor.deactivate()

    def receive_input(self, content: str, source_trust: SourceTrust) -> str:
        """
        Registriert einen externen Input.
        Setzt Contamination Tag wenn untrusted.
        Gibt content_hash zurück für Source Lineage.
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
        Zentrale Execute-Methode (synchron).
        Gibt True zurück wenn Aktion ausgeführt wurde.
        """
        # Contamination Tag übertragen
        action.contaminated = self._contaminated
        action.session_id   = self.audit.session_id

        # Gate evaluieren
        result = self.gate.evaluate(action)

        # Ergebnis loggen
        self._log_gate_result(result)

        if result.decision == Decision.ALLOW:
            self.audit.log_tool_call(
                action.action_id, action.tool.value,
                f"Ausgeführt: {action.verb.value} → {action.target}", True,
            )
            return True

        elif result.decision == Decision.ASK:
            self.audit.log_gate_prompt(action.action_id, result.preview or {})

            if self.auto_deny_ask:
                logger.info("[Auto-DENY] non-interactive Modus")
                self.audit.log_human_decision(action.action_id, "auto_deny")
                return False

            # Interaktive Bestätigung
            approved = self._ask_human(result)
            choice   = "approve" if approved else "deny"
            self.audit.log_human_decision(action.action_id, choice)

            if approved:
                self.audit.log_tool_call(
                    action.action_id, action.tool.value,
                    f"Ausgeführt nach Bestätigung: {action.verb.value} → {action.target}", True,
                )
            return approved

        else:  # DENY
            self.audit.log_tool_call(
                action.action_id, action.tool.value,
                f"GEBLOCKT: {action.verb.value} → {action.target}", False,
            )
            return False

    async def _execute_async(self, action: Action) -> bool:
        """
        Async-Wrapper für _execute().

        Führt die synchrone Gate-Logik in einem ThreadPool-Executor aus.
        Für non-interactive Nutzung (auto_deny_ask=True) empfohlen.
        """
        import asyncio
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._execute, action)

    def _log_gate_result(self, result: GateResult) -> None:
        """Logt Gate-Entscheidung via logging.info."""
        icons  = {Decision.ALLOW: "✅", Decision.ASK: "⚠️ ", Decision.DENY: "🛑"}
        icon   = icons[result.decision]
        target = result.action.target or "(kein Ziel)"
        logger.info(
            "%s GATE [%s] %s → %s | Score: %d/100 | Rules: %s",
            icon,
            result.decision.value,
            result.action.verb.value.upper(),
            target,
            result.risk_score,
            ", ".join(result.matched_rule_ids),
        )
        for reason in result.reasons:
            logger.info("   Grund: %s", reason)

    def _ask_human(self, result: GateResult) -> bool:
        """Interaktive Bestätigung (sync, blockierend)."""
        print(f"\n  📋 PREVIEW:")
        if result.preview:
            for k, v in result.preview.items():
                print(f"     {k}: {v}")
        response = input("\n  → Aktion genehmigen? [j/n]: ").strip().lower()
        return response in {"j", "ja", "y", "yes"}

    def export_audit(self, filepath: str = "immunegate_audit.json") -> None:
        """Exportiert den Audit Log als JSON-Datei."""
        self.audit.export_json(filepath)

    def print_summary(self) -> None:
        """Gibt Session Summary auf der Konsole aus."""
        self.audit.print_summary()


# ─── SUB-WRAPPERS ─────────────────────────────────────────────────────────────

class _FilesWrapper:
    def __init__(self, ig: ImmuneGate) -> None:
        self._ig = ig

    def read(self, path: str) -> bool:
        return self._ig._execute(Action(
            verb         = Verb.READ,
            tool         = Tool.FILES,
            destination  = Destination.INTERNAL,
            target       = path,
            source_trust = SourceTrust.INTERNAL_SYSTEM,
        ))

    async def read_async(self, path: str) -> bool:
        return await self._ig._execute_async(Action(
            verb         = Verb.READ,
            tool         = Tool.FILES,
            destination  = Destination.INTERNAL,
            target       = path,
            source_trust = SourceTrust.INTERNAL_SYSTEM,
        ))

    def write(self, path: str, content: str = "", sensitive: bool = False) -> bool:
        verb = Verb.WRITE_SENSITIVE if sensitive else Verb.WRITE
        ds   = detect_danger_signals(content)
        return self._ig._execute(Action(
            verb         = verb,
            tool         = Tool.FILES,
            destination  = Destination.INTERNAL,
            target       = path,
            content      = content,
            danger_signals = ds,
            source_trust = self._ig._get_current_source_trust(),
        ))

    async def write_async(self, path: str, content: str = "", sensitive: bool = False) -> bool:
        verb = Verb.WRITE_SENSITIVE if sensitive else Verb.WRITE
        ds   = detect_danger_signals(content)
        return await self._ig._execute_async(Action(
            verb           = verb,
            tool           = Tool.FILES,
            destination    = Destination.INTERNAL,
            target         = path,
            content        = content,
            danger_signals = ds,
            source_trust   = self._ig._get_current_source_trust(),
        ))

    def delete(self, path: str) -> bool:
        ds = detect_danger_signals(path)
        return self._ig._execute(Action(
            verb           = Verb.DELETE,
            tool           = Tool.FILES,
            destination    = Destination.INTERNAL,
            target         = path,
            danger_signals = ds,
            source_trust   = self._ig._get_current_source_trust(),
        ))

    async def delete_async(self, path: str) -> bool:
        ds = detect_danger_signals(path)
        return await self._ig._execute_async(Action(
            verb           = Verb.DELETE,
            tool           = Tool.FILES,
            destination    = Destination.INTERNAL,
            target         = path,
            danger_signals = ds,
            source_trust   = self._ig._get_current_source_trust(),
        ))


class _EmailWrapper:
    def __init__(self, ig: ImmuneGate) -> None:
        self._ig = ig

    def send(self, recipient: str, subject: str, body: str = "") -> bool:
        domain       = recipient.split("@")[-1] if "@" in recipient else recipient
        internal_set = (
            set(self._ig.config.internal_domains)
            if self._ig.config
            else {"company.com", "intern.local"}
        )
        destination  = (
            Destination.INTERNAL if domain in internal_set else Destination.EXTERNAL
        )
        ds = detect_danger_signals(f"{subject} {body}")
        return self._ig._execute(Action(
            verb           = Verb.SEND,
            tool           = Tool.EMAIL,
            destination    = destination,
            target         = recipient,
            content        = f"Subject: {subject}\n\n{body}",
            danger_signals = ds,
            source_trust   = self._ig._get_current_source_trust(),
        ))

    async def send_async(self, recipient: str, subject: str, body: str = "") -> bool:
        domain       = recipient.split("@")[-1] if "@" in recipient else recipient
        internal_set = (
            set(self._ig.config.internal_domains)
            if self._ig.config
            else {"company.com", "intern.local"}
        )
        destination  = (
            Destination.INTERNAL if domain in internal_set else Destination.EXTERNAL
        )
        ds = detect_danger_signals(f"{subject} {body}")
        return await self._ig._execute_async(Action(
            verb           = Verb.SEND,
            tool           = Tool.EMAIL,
            destination    = destination,
            target         = recipient,
            content        = f"Subject: {subject}\n\n{body}",
            danger_signals = ds,
            source_trust   = self._ig._get_current_source_trust(),
        ))


class _WebWrapper:
    def __init__(self, ig: ImmuneGate) -> None:
        self._ig = ig

    def browse(self, url: str) -> bool:
        return self._ig._execute(Action(
            verb         = Verb.BROWSE,
            tool         = Tool.WEB,
            destination  = Destination.EXTERNAL,
            target       = url,
            source_trust = SourceTrust.USER_DIRECT,
        ))

    async def browse_async(self, url: str) -> bool:
        return await self._ig._execute_async(Action(
            verb         = Verb.BROWSE,
            tool         = Tool.WEB,
            destination  = Destination.EXTERNAL,
            target       = url,
            source_trust = SourceTrust.USER_DIRECT,
        ))

    def receive_content(self, url: str, content: str) -> str:
        """Web-Inhalt empfangen und als untrusted registrieren."""
        return self._ig.receive_input(content, SourceTrust.WEB)


class _ShellWrapper:
    """Shell-Ausführung durch das Gate (subprocess-Schutz)."""

    def __init__(self, ig: ImmuneGate) -> None:
        self._ig = ig

    def execute(self, command: str) -> bool:
        """Shell-Befehl durch Gate evaluieren. PRR-009 → immer DENY."""
        ds = detect_danger_signals(command)
        return self._ig._execute(Action(
            verb           = Verb.EXECUTE,
            tool           = Tool.SHELL,
            destination    = Destination.INTERNAL,
            target         = command[:200],
            content        = command,
            danger_signals = ds,
            source_trust   = self._ig._get_current_source_trust(),
        ))

    async def execute_async(self, command: str) -> bool:
        ds = detect_danger_signals(command)
        return await self._ig._execute_async(Action(
            verb           = Verb.EXECUTE,
            tool           = Tool.SHELL,
            destination    = Destination.INTERNAL,
            target         = command[:200],
            content        = command,
            danger_signals = ds,
            source_trust   = self._ig._get_current_source_trust(),
        ))


class _FtpWrapper:
    """FTP-Transfers durch das Gate."""

    def __init__(self, ig: ImmuneGate) -> None:
        self._ig = ig

    def upload(self, server: str, path: str) -> bool:
        """FTP-Upload durch Gate evaluieren. Score 90 → DENY."""
        return self._ig._execute(Action(
            verb         = Verb.UPLOAD,
            tool         = Tool.FTP,
            destination  = Destination.EXTERNAL,
            target       = f"{server}/{path}",
            source_trust = self._ig._get_current_source_trust(),
        ))

    async def upload_async(self, server: str, path: str) -> bool:
        return await self._ig._execute_async(Action(
            verb         = Verb.UPLOAD,
            tool         = Tool.FTP,
            destination  = Destination.EXTERNAL,
            target       = f"{server}/{path}",
            source_trust = self._ig._get_current_source_trust(),
        ))


class _SshWrapper:
    """SSH-Ausführung durch das Gate (paramiko-Schutz)."""

    def __init__(self, ig: ImmuneGate) -> None:
        self._ig = ig

    def exec_command(self, host: str, command: str) -> bool:
        """SSH-Befehl durch Gate evaluieren. PRR-009 → immer DENY."""
        ds = detect_danger_signals(command)
        return self._ig._execute(Action(
            verb           = Verb.EXECUTE,
            tool           = Tool.SSH,
            destination    = Destination.EXTERNAL,
            target         = f"{host}: {command[:100]}",
            content        = command,
            danger_signals = ds,
            source_trust   = self._ig._get_current_source_trust(),
        ))

    async def exec_command_async(self, host: str, command: str) -> bool:
        ds = detect_danger_signals(command)
        return await self._ig._execute_async(Action(
            verb           = Verb.EXECUTE,
            tool           = Tool.SSH,
            destination    = Destination.EXTERNAL,
            target         = f"{host}: {command[:100]}",
            content        = command,
            danger_signals = ds,
            source_trust   = self._ig._get_current_source_trust(),
        ))


# ─── HELPER ───────────────────────────────────────────────────────────────────

def _get_current_source_trust(self: ImmuneGate) -> SourceTrust:
    """Gibt aktuelle Source Trust zurück (kontaminiert = web-level)."""
    if self._contaminated:
        return SourceTrust.WEB
    return SourceTrust.USER_DIRECT

# Monkey-patch auf ImmuneGate
ImmuneGate._get_current_source_trust = _get_current_source_trust
