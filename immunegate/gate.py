"""
ImmuneGate – Permission Gate
Der zentrale Entscheidungspunkt. Kein Toolcall passiert ohne Gate.
"""

from __future__ import annotations
import time
from collections import deque
from typing import Optional
from .schemas import Action, Decision, GateResult, ScoreBreakdown
from .risk_engine import calculate_score, score_to_decision
from .policy_engine import evaluate_policies, apply_precedence
from .audit import AuditLog


class PermissionGate:
    """
    Hauptklasse. Evaluiert jede Action und gibt GateResult zurück.

    Precedence: DENY > ALLOW > ASK > Score Fallback
    Fail-Safe: bei jedem Fehler → DENY
    Rate-Limiting: max N Aktionen pro Zeitfenster (konfigurierbar)
    """

    def __init__(self, audit_log: AuditLog, config=None, plugins=None):
        self.audit    = audit_log
        self.config   = config
        self._plugins = plugins or []
        self._rate_timestamps: deque = deque()  # Rolling-Window für Rate-Limiting

    def _check_rate_limit(self) -> bool:
        """
        Rate-Limit prüfen (rolling window).
        Returns True wenn Aktion erlaubt ist, False wenn Limit überschritten.
        """
        if not self.config:
            return True
        max_actions = self.config.rate_limit_max_actions
        window_secs = self.config.rate_limit_window_seconds
        if max_actions <= 0 or window_secs <= 0:
            return True  # Rate-Limiting deaktiviert

        now = time.monotonic()
        # Alte Timestamps außerhalb des Fensters entfernen
        while self._rate_timestamps and now - self._rate_timestamps[0] > window_secs:
            self._rate_timestamps.popleft()

        if len(self._rate_timestamps) >= max_actions:
            return False  # Limit überschritten → DENY

        self._rate_timestamps.append(now)
        return True

    async def evaluate_async(self, action: Action) -> GateResult:
        """
        Async-Wrapper für evaluate().

        Führt die synchrone Gate-Logik in einem ThreadPool-Executor aus,
        damit der Event-Loop nicht blockiert wird.

        Beispiel:
            result = await gate.evaluate_async(action)
        """
        import asyncio
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.evaluate, action)

    def evaluate(self, action: Action) -> GateResult:
        """
        Evaluiert eine Action. Gibt immer ein GateResult zurück.
        Bei jedem internen Fehler: DENY (fail-safe).
        """
        try:
            return self._evaluate_safe(action)
        except Exception as e:
            # Fail-Safe Default: Engine-Fehler → DENY
            result = GateResult(
                action           = action,
                decision         = Decision.DENY,
                risk_score       = 100,
                score_breakdown  = ScoreBreakdown(),
                matched_rule_ids = ["ENGINE_ERROR"],
                reasons          = [f"Gate engine error: {str(e)} → fail-safe DENY"],
            )
            self.audit.log_risk_evaluated(result, error=str(e))
            return result

    def _evaluate_safe(self, action: Action) -> GateResult:
        # 0. Rate-Limit prüfen (vor allem anderen)
        if not self._check_rate_limit():
            max_a = self.config.rate_limit_max_actions if self.config else "?"
            win_s = self.config.rate_limit_window_seconds if self.config else "?"
            result = GateResult(
                action           = action,
                decision         = Decision.DENY,
                risk_score       = 100,
                score_breakdown  = ScoreBreakdown(),
                matched_rule_ids = ["RATE_LIMIT_EXCEEDED"],
                reasons          = [
                    f"Rate-Limit überschritten: max. {max_a} Aktionen pro {win_s}s",
                ],
            )
            self.audit.log_risk_evaluated(result)
            return result

        # 1. Score berechnen
        breakdown   = calculate_score(action)
        risk_score  = breakdown.total

        # 2. Core Policy Engine evaluieren
        matches     = evaluate_policies(action, config=self.config)

        # 2b. Plugins ausführen (nach Core, vor Precedence-Entscheidung)
        #     Fail-Safe: Fehler in run_plugins → leere Liste, Gate läuft weiter
        if self._plugins:
            from .plugins import run_plugins
            plugin_matches = run_plugins(self._plugins, action)
            matches.extend(plugin_matches)

        top_match   = apply_precedence(matches)

        # 3. Entscheidung treffen
        is_fallback = False

        if top_match:
            decision         = top_match.decision
            matched_rule_ids = [m.rule_id for m in matches if m.decision == decision]
            reasons          = self._build_reasons(action, matches, risk_score, decision)
        else:
            # Score Fallback (kein Policy-Match)
            decision         = score_to_decision(risk_score, config=self.config)
            matched_rule_ids = ["SCORE_FALLBACK"]
            reasons          = [f"Score fallback: {risk_score}/100 → {decision.value}",
                                 self._score_reason(action, breakdown)]
            is_fallback      = True

        # 4. Preview Spec (nur bei ASK)
        preview = None
        if decision == Decision.ASK:
            preview = self._build_preview_spec(action)
            if preview is None:
                # Fail-Safe: kein Preview möglich → DENY statt ASK
                decision         = Decision.DENY
                matched_rule_ids.append("PREVIEW_UNAVAILABLE")
                reasons.append("Preview konnte nicht generiert werden → DENY statt ASK")

        result = GateResult(
            action            = action,
            decision          = decision,
            risk_score        = risk_score,
            score_breakdown   = breakdown,
            matched_rule_ids  = matched_rule_ids,
            reasons           = reasons,
            preview           = preview,
            is_score_fallback = is_fallback,
        )

        self.audit.log_risk_evaluated(result)
        return result

    def _build_reasons(self, action, matches, score, decision) -> list[str]:
        """Baut Top-2 Gründe für die Entscheidung."""
        reasons = []

        # Primärgrund: Was hat die Entscheidung getriggert?
        for m in matches:
            if m.decision == decision:
                reasons.append(f"[{m.rule_id}] {m.reason}")
                break

        # Sekundärgrund: Risk Score + Kontext
        if action.danger_signals:
            reasons.append(f"Danger Signals erkannt: {', '.join(s.value for s in action.danger_signals)}")
        elif score >= 70:
            reasons.append(f"Risk Score {score}/100 (High)")
        elif score >= 40:
            reasons.append(f"Risk Score {score}/100 (Medium)")

        return reasons[:2]  # Max Top-2

    def _score_reason(self, action, breakdown) -> str:
        parts = [f"Impact({action.verb.value})={breakdown.impact}"]
        if breakdown.trust_modifier != 0:
            parts.append(f"TrustMod={breakdown.trust_modifier:+d}")
        if breakdown.danger_sum > 0:
            parts.append(f"DangerSum={breakdown.danger_sum}")
        if breakdown.behavior_bonus > 0:
            parts.append(f"BehaviorBonus={breakdown.behavior_bonus}")
        return " + ".join(parts) + f" = {breakdown.total}"

    def _build_preview_spec(self, action) -> dict | None:
        """
        Erstellt Preview-Spec für die Approval UI.
        Gibt None zurück wenn Preview nicht generierbar → Gate wird DENY.
        
        HINWEIS: Dies ist der Platzhalter für den dry-run Mechanismus.
        In Sprint 2 wird hier der echte dry-run implementiert.
        """
        from .schemas import Verb

        if action.verb == Verb.DELETE:
            if not action.target:
                return None
            return {
                "type":          "delete",
                "target":        action.target,
                "warning":       "Diese Aktion ist NICHT umkehrbar ohne Backup!",
                "recovery_plan": "Prüfe ob Papierkorb / Snapshot verfügbar.",
                "dry_run_note":  "⚠️ Dry-run Implementierung ausstehend (Sprint 2)",
            }

        elif action.verb == Verb.SEND:
            if not action.target:
                return None
            return {
                "type":       "send",
                "recipient":  action.target,
                "domain":     action.target.split("@")[-1] if "@" in action.target else action.target,
                "content":    action.content[:500] if action.content else "(kein Inhalt)",
                "warning":    "Externe Kommunikation – Empfänger sorgfältig prüfen!",
            }

        elif action.verb == Verb.UPLOAD:
            return {
                "type":        "upload",
                "destination": action.target,
                "visibility":  "unknown",
                "warning":     "Datei wird extern zugänglich – Inhalt prüfen!",
            }

        elif action.verb in {Verb.WRITE, Verb.WRITE_SENSITIVE}:
            return {
                "type":        "write",
                "target":      action.target,
                "sensitivity": action.sensitivity_label.value,
                "content":     action.content[:300] if action.content else "(kein Inhalt)",
                "diff_note":   "⚠️ Diff-Implementierung ausstehend (Sprint 2)",
            }

        # Für alle anderen Verben: kein Preview nötig
        return {"type": "generic", "target": action.target}
