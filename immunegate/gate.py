"""
ImmuneGate – Permission Gate
Der zentrale Entscheidungspunkt. Kein Toolcall passiert ohne Gate.
"""

import os
from datetime import datetime
from .schemas import Action, Decision, GateResult, ScoreBreakdown
from .risk_engine import calculate_score, score_to_decision
from .policy_engine import evaluate_policies, apply_precedence
from .audit import AuditLog

_DRY_RUN_MAX_FILES = 200  # Sicherheitslimit – mehr Dateien → abgeschnitten


class PermissionGate:
    """
    Hauptklasse. Evaluiert jede Action und gibt GateResult zurück.
    
    Precedence: DENY > ALLOW > ASK > Score Fallback
    Fail-Safe: bei jedem Fehler → DENY
    """

    def __init__(self, audit_log: AuditLog):
        self.audit = audit_log

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
        # 1. Score berechnen
        breakdown   = calculate_score(action)
        risk_score  = breakdown.total

        # 2. Policy Engine evaluieren
        matches     = evaluate_policies(action)
        top_match   = apply_precedence(matches)

        # 3. Entscheidung treffen
        is_fallback = False

        if top_match:
            decision         = top_match.decision
            matched_rule_ids = [m.rule_id for m in matches if m.decision == decision]
            reasons          = self._build_reasons(action, matches, risk_score, decision)
        else:
            # Score Fallback (kein Policy-Match)
            decision         = score_to_decision(risk_score)
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

    def _build_preview_spec(self, action):
        """
        Erstellt Preview-Spec für die Approval UI.
        Gibt None zurück wenn Preview nicht generierbar → Gate wird DENY.
        """
        from .schemas import Verb

        if action.verb == Verb.DELETE:
            if not action.target:
                return None
            files = self._dry_run_scan(action.target)
            if files is None:
                # Scan fehlgeschlagen (Pfad existiert nicht / kein Zugriff) → Fail-Safe
                return None
            return {
                "type":          "delete",
                "target":        action.target,
                "files":         files,
                "file_count":    len(files),
                "warning":       "Diese Aktion ist NICHT umkehrbar ohne Backup!",
                "recovery_plan": "Prüfe ob Papierkorb / Snapshot verfügbar. Erstelle vor Ausführung ein Backup.",
            }

        elif action.verb == Verb.SEND:
            if not action.target:
                return None
            subject, body = self._parse_email_content(action.content)
            domain        = action.target.split("@")[-1] if "@" in action.target else action.target
            return {
                "type":        "send",
                "recipient":   action.target,
                "domain":      domain,
                "domain_risk": self._classify_domain_risk(domain),
                "subject":     subject,
                "body":        body,
                "warning":     "Externe Kommunikation – Empfänger und Inhalt sorgfältig prüfen!",
            }

        elif action.verb == Verb.UPLOAD:
            return {
                "type":        "upload",
                "destination": action.target,
                "visibility":  "unknown",
                "warning":     "Datei wird extern zugänglich – Inhalt prüfen!",
            }

        elif action.verb in {Verb.WRITE, Verb.WRITE_SENSITIVE}:
            before, is_new = self._read_existing_file(action.target)
            return {
                "type":        "write",
                "target":      action.target,
                "sensitivity": action.sensitivity_label.value,
                "is_new_file": is_new,
                "before":      before,
                "after":       action.content or "",
            }

        # Für alle anderen Verben: kein Preview nötig
        return {"type": "generic", "target": action.target}

    def _parse_email_content(self, content: str):
        """
        Extrahiert Subject und Body aus action.content.
        Format erwartet: "Subject: {subject}\n\n{body}"
        Gibt (subject, body) zurück.
        """
        if not content:
            return ("", "")
        if content.startswith("Subject:"):
            parts = content.split("\n\n", 1)
            subject = parts[0].replace("Subject:", "").strip()
            body    = parts[1].strip() if len(parts) > 1 else ""
        else:
            subject = ""
            body    = content
        return (subject, body)

    def _classify_domain_risk(self, domain: str) -> str:
        """
        Klassifiziert das Risiko einer E-Mail-Domain.
        Gibt "high", "medium" oder "low" zurück.
        """
        high_risk = {
            "gmail.com", "yahoo.com", "yahoo.de", "hotmail.com", "hotmail.de",
            "outlook.com", "live.com", "protonmail.com", "icloud.com",
            "aol.com", "gmx.com", "gmx.de", "web.de", "t-online.de",
        }
        low_risk = {"company.com", "intern.local"}

        d = domain.lower().strip()
        if d in high_risk:
            return "high"
        if d in low_risk:
            return "low"
        return "medium"

    def _read_existing_file(self, path: str):
        """
        Liest den aktuellen Inhalt einer Datei für den Write-Diff.
        Gibt (content, is_new_file) zurück.
        is_new_file=True wenn die Datei noch nicht existiert.
        Fail-safe: bei Lesefehler → ("", True) – kein DENY, Diff zeigt nur Hinzugefügtes.
        """
        try:
            if not path or not os.path.isfile(path):
                return ("", True)
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                return (f.read(), False)
        except OSError:
            return ("", True)

    def _dry_run_scan(self, target: str):
        """
        Read-only Vorab-Scan für delete-Targets.
        Gibt Liste von {path, size, modified} zurück, oder None bei Fehler.
        None → Gate setzt Entscheidung auf DENY (Fail-Safe).
        """
        try:
            if not os.path.exists(target):
                return None  # Pfad existiert nicht → Fail-Safe DENY

            files = []

            if os.path.isfile(target):
                stat = os.stat(target)
                files.append({
                    "path":     target,
                    "size":     stat.st_size,
                    "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="seconds"),
                })
            elif os.path.isdir(target):
                for dirpath, _dirnames, filenames in os.walk(target):
                    for fname in filenames:
                        if len(files) >= _DRY_RUN_MAX_FILES:
                            break
                        fpath = os.path.join(dirpath, fname)
                        try:
                            stat = os.stat(fpath)
                            files.append({
                                "path":     fpath,
                                "size":     stat.st_size,
                                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="seconds"),
                            })
                        except OSError:
                            # Einzelne Datei nicht lesbar → überspringen, Scan läuft weiter
                            pass
                    if len(files) >= _DRY_RUN_MAX_FILES:
                        break
            else:
                return None  # Weder Datei noch Verzeichnis → Fail-Safe DENY

            return files

        except PermissionError:
            return None  # Kein Zugriff → Fail-Safe DENY
        except OSError:
            return None  # Anderer OS-Fehler → Fail-Safe DENY
