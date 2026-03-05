"""
ImmuneGate – Blackbox Audit / Flight Recorder
Loggt alle Events. Export als JSON + Session Summary.
"""

import json
import uuid
from datetime import datetime
from dataclasses import asdict
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .schemas import GateResult, Action


class AuditLog:
    """
    Flight Recorder: loggt jeden Event in der Session-Timeline.
    Alle Entscheidungen sind nachvollziehbar und exportierbar.
    """

    def __init__(self, session_id: Optional[str] = None):
        self.session_id = session_id or str(uuid.uuid4())
        self.events: list[dict] = []
        self._allow_count  = 0
        self._ask_count    = 0
        self._deny_count   = 0
        self._approve_count= 0
        self._reject_count = 0

    # ─── EVENT LOGGING ────────────────────────────────────────────────────────

    def log_input_received(self, source_kind: str, trust_modifier: int,
                           danger_signals: list, content_hash: str = ""):
        self._add_event("input_received", {
            "source_kind":    source_kind,
            "trust_modifier": trust_modifier,
            "danger_signals": danger_signals,
            "content_hash":   content_hash,
        })

    def log_agent_intent(self, intent_summary: str, source_lineage: list,
                         untrusted_flag: bool = False):
        self._add_event("agent_intent", {
            "intent_summary": intent_summary,
            "source_lineage": source_lineage,
            "untrusted_flag": untrusted_flag,
        })

    def log_risk_evaluated(self, result: "GateResult", error: str = ""):
        from .schemas import Decision
        decision = result.decision.value

        if result.decision == Decision.ALLOW:
            self._allow_count += 1
        elif result.decision == Decision.ASK:
            self._ask_count += 1
        elif result.decision == Decision.DENY:
            self._deny_count += 1

        self._add_event("risk_evaluated", {
            "action_id":        result.action.action_id,
            "verb":             result.action.verb.value,
            "tool":             result.action.tool.value,
            "target":           result.action.target,
            "decision":         decision,
            "risk_score":       result.risk_score,
            "score_breakdown": {
                "impact":          result.score_breakdown.impact,
                "trust_modifier":  result.score_breakdown.trust_modifier,
                "danger_sum":      result.score_breakdown.danger_sum,
                "behavior_bonus":  result.score_breakdown.behavior_bonus,
                "total":           result.score_breakdown.total,
            },
            "matched_rule_ids": result.matched_rule_ids,
            "reasons":          result.reasons,
            "is_score_fallback":result.is_score_fallback,
            "danger_signals":  [s.value for s in result.action.danger_signals],
            "contaminated":     result.action.contaminated,
            "error":            error,
        })

    def log_gate_prompt(self, action_id: str, preview: dict):
        self._add_event("gate_prompt", {
            "action_id":   action_id,
            "preview":     preview,
            "ui_shown_at": datetime.now().isoformat(),
        })

    def log_human_decision(self, action_id: str, choice: str, latency_ms: int = 0):
        if choice == "approve":
            self._approve_count += 1
        else:
            self._reject_count += 1

        self._add_event("human_decision", {
            "action_id":  action_id,
            "choice":     choice,
            "latency_ms": latency_ms,
        })

    def log_tool_call(self, action_id: str, tool: str, result_summary: str, success: bool):
        self._add_event("tool_call", {
            "action_id":      action_id,
            "tool":           tool,
            "result_summary": result_summary,
            "success":        success,
        })

    # ─── SESSION SUMMARY ──────────────────────────────────────────────────────

    def get_session_summary(self) -> dict:
        total = self._allow_count + self._ask_count + self._deny_count
        return {
            "session_id":              self.session_id,
            "total_actions":           total,
            "allow_count":             self._allow_count,
            "ask_count":               self._ask_count,
            "deny_count":              self._deny_count,
            "approve_count":           self._approve_count,
            "reject_count":            self._reject_count,
            "approval_rate":           round(self._approve_count / max(self._ask_count, 1) * 100, 1),
            "deny_rate":               round(self._deny_count / max(total, 1) * 100, 1),
            "top_rules":               self._get_top_rules(),
            "untrusted_influence_rate":self._get_untrusted_influence_rate(),
        }

    def _get_top_rules(self) -> list:
        rule_counts: dict[str, int] = {}
        for event in self.events:
            if event["event_type"] == "risk_evaluated":
                for rule_id in event["payload"].get("matched_rule_ids", []):
                    rule_counts[rule_id] = rule_counts.get(rule_id, 0) + 1
        sorted_rules = sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)
        return [{"rule_id": r, "count": c} for r, c in sorted_rules[:3]]

    def _get_untrusted_influence_rate(self) -> float:
        risk_events = [e for e in self.events if e["event_type"] == "risk_evaluated"]
        if not risk_events:
            return 0.0
        risky_verbs = {"delete", "send", "upload", "write", "write_sensitive"}
        influenced = sum(
            1 for e in risk_events
            if e["payload"].get("contaminated")
            and e["payload"].get("verb") in risky_verbs
        )
        return round(influenced / len(risk_events) * 100, 1)

    # ─── EXPORT ───────────────────────────────────────────────────────────────

    def export_json(self, filepath: str):
        """Exportiert vollständigen Audit Log als JSON."""
        export = {
            "session_id":      self.session_id,
            "exported_at":     datetime.now().isoformat(),
            "policy_version":  "1.0",
            "events":          self.events,
            "session_summary": self.get_session_summary(),
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(export, f, indent=2, ensure_ascii=False)
        print(f"✅ Audit Log exportiert: {filepath}")

    def print_summary(self):
        """Zeigt Session Summary in der Konsole."""
        summary = self.get_session_summary()
        print("\n" + "═" * 55)
        print("  IMMUNEGATE – SESSION SUMMARY")
        print("═" * 55)
        print(f"  Session:      {summary['session_id'][:8]}...")
        print(f"  Total Actions:{summary['total_actions']}")
        print(f"  ✅ ALLOW:     {summary['allow_count']}")
        print(f"  ⚠️  ASK:      {summary['ask_count']}")
        print(f"  🛑 DENY:      {summary['deny_count']}")
        print(f"  Approval Rate:{summary['approval_rate']}%")
        print(f"  Deny Rate:    {summary['deny_rate']}%")
        print(f"  Untrusted Inf:{summary['untrusted_influence_rate']}%")
        if summary['top_rules']:
            print("  Top Rules:")
            for r in summary['top_rules']:
                print(f"    → {r['rule_id']}: {r['count']}x")
        print("═" * 55 + "\n")

    # ─── INTERNAL ─────────────────────────────────────────────────────────────

    def _add_event(self, event_type: str, payload: dict):
        self.events.append({
            "event_id":   str(uuid.uuid4()),
            "session_id": self.session_id,
            "event_type": event_type,
            "timestamp":  datetime.now().isoformat(),
            "payload":    payload,
        })
