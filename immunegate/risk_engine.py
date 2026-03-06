"""
ImmuneGate – Risk Scoring Engine
Deterministisch, auditierbar, keine LLM-Abhängigkeit.
"""

from .schemas import Action, ScoreBreakdown, Decision, Verb, SourceTrust, DangerSignal, BehaviorFlag

# ─── IMPACT TABLE ─────────────────────────────────────────────────────────────

IMPACT: dict[Verb, int] = {
    Verb.SEND:           95,
    Verb.UPLOAD:         90,
    Verb.DELETE:         85,
    Verb.WRITE_SENSITIVE:80,
    Verb.WRITE:          60,
    Verb.READ_SENSITIVE: 55,
    Verb.READ:           20,
    Verb.BROWSE:         10,
}

# ─── TRUST MODIFIER TABLE ─────────────────────────────────────────────────────

TRUST_MODIFIER: dict[SourceTrust, int] = {
    SourceTrust.INTERNAL_SYSTEM: -10,
    SourceTrust.USER_DIRECT:       0,
    SourceTrust.INTERNAL_DOC:     +5,
    SourceTrust.EMAIL_INTERNAL:  +10,
    SourceTrust.UNKNOWN:         +10,
    SourceTrust.EMAIL_EXTERNAL:  +20,
    SourceTrust.WEB:             +25,
}

# ─── DANGER SIGNAL BONUSES ────────────────────────────────────────────────────

DANGER_BONUS: dict[DangerSignal, int] = {
    DangerSignal.INJ_OVERRIDE: 25,
    DangerSignal.EXFILTRATION: 30,
    DangerSignal.CREDENTIALS:  35,
    DangerSignal.MASS_DESTRUCT:35,
    DangerSignal.STEALTH:      25,
}

# ─── BEHAVIOR BONUSES ─────────────────────────────────────────────────────────

BEHAVIOR_BONUS: dict[BehaviorFlag, int] = {
    BehaviorFlag.BURST_RISK:          15,
    BehaviorFlag.NEW_EXTERNAL_TARGET: 10,
}

# ─── SCORE THRESHOLDS ─────────────────────────────────────────────────────────

def score_to_decision(score: int, config=None) -> Decision:
    """Score Fallback – nur wenn keine Policy greift."""
    allow_max = config.allow_max if config else 39
    ask_max   = config.ask_max   if config else 69
    if score <= allow_max:
        return Decision.ALLOW
    elif score <= ask_max:
        return Decision.ASK
    else:
        return Decision.DENY


# ─── MAIN SCORING FUNCTION ────────────────────────────────────────────────────

def calculate_score(action: Action) -> ScoreBreakdown:
    """
    Berechnet risk_score deterministisch.
    Formel: impact + trust_modifier + danger_sum + behavior_bonus, clamp 0–100
    """
    impact         = IMPACT.get(action.verb, 50)
    trust_mod      = TRUST_MODIFIER.get(action.source_trust, 10)
    danger_sum     = sum(DANGER_BONUS.get(sig, 0) for sig in action.danger_signals)
    behavior_bonus = sum(BEHAVIOR_BONUS.get(flag, 0) for flag in action.behavior_flags)

    return ScoreBreakdown(
        impact         = impact,
        trust_modifier = trust_mod,
        danger_sum     = danger_sum,
        behavior_bonus = behavior_bonus,
    )
