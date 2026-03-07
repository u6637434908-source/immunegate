"""
ImmuneGate – OWASP LLM Top 10 Mapping

Jede Policy-Regel ist mindestens einem OWASP LLM Top 10 Risiko (2025 Edition)
zugeordnet. Das Mapping ermöglicht Compliance-Nachweise gegenüber Auditoren
und zeigt, welche Angriffsvektoren durch ImmuneGate abgedeckt werden.

Referenz:
    https://owasp.org/www-project-top-10-for-large-language-model-applications/
    OWASP LLM Top 10 – v2.0 (2025)

EU AI Act Relevanz:
    Art. 9  – Risikomanagement: Nachvollziehbare Entscheidungen (Audit Log)
    Art. 10 – Datenqualität: Schutz vor vergifteten Eingaben (PRR-003/004)
    Art. 13 – Transparenz: Regel-IDs + OWASP-Refs im Audit Log
    Art. 14 – Menschliche Aufsicht: ASK-Entscheidungen (PRR-002/006/TOL-003)
"""

from __future__ import annotations

# ─── OWASP LLM TOP 10 (2025) ─────────────────────────────────────────────────

OWASP_CATEGORIES: dict[str, str] = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}

# ─── REGEL → OWASP MAPPING ───────────────────────────────────────────────────
#
# Leer = Regel mitigiert ein Risiko, schlägt aber selbst keinen OWASP-Angriff auf
# (z. B. PRR-005: READ → ALLOW – risikoarm, keine Bedrohung)

RULE_OWASP_MAPPING: dict[str, list[str]] = {
    # ── PRR: Primär-Reflexregeln ──────────────────────────────────────────────
    "PRR-001": ["LLM02"],           # Credentials-Exfiltration → Sensitive Info Disclosure
    "PRR-002": ["LLM06"],           # Jede Löschaktion → ASK → Excessive Agency
    "PRR-003": ["LLM01", "LLM06"], # Untrusted Source sendet extern → Prompt Injection + Excessive Agency
    "PRR-004": ["LLM01"],           # Write unter Fremdeinfluss → Prompt Injection
    "PRR-005": [],                  # Read → ALLOW – risikoarm, mitigiert
    "PRR-006": ["LLM02"],           # Read Sensitive → ASK → Sensitive Info Disclosure
    "PRR-007": ["LLM01", "LLM06"], # MASS_DESTRUCT Signal → Prompt Injection + Excessive Agency
    "PRR-008": ["LLM01", "LLM06"], # STEALTH Signal → Prompt Injection + Excessive Agency

    # ── TOL: Toleranzregeln ───────────────────────────────────────────────────
    "TOL-001": [],                  # Send internal Allowlist → ALLOW – mitigiert
    "TOL-002": [],                  # Delete Sandbox → ALLOW – mitigiert
    "TOL-003": ["LLM06"],           # Neue externe Domain → ASK → Excessive Agency
}

# ─── GATE-RELEVANTE KATEGORIEN ────────────────────────────────────────────────
# OWASP-Kategorien die ein Policy-Gate sinnvoll adressieren kann.
# LLM03/04/08/09/10 = Training/Modell-Schicht, außerhalb des Gate-Scope.

GATE_RELEVANT_CATEGORIES: set[str] = {"LLM01", "LLM02", "LLM05", "LLM06", "LLM07"}


# ─── PUBLIC API ──────────────────────────────────────────────────────────────

def get_owasp_refs(rule_id: str) -> list[str]:
    """
    Gibt OWASP LLM Top 10 Kategorien für eine Policy-Regel zurück.

    Args:
        rule_id: z. B. "PRR-001"

    Returns:
        Liste mit OWASP-IDs (z. B. ["LLM01", "LLM06"]).
        Leere Liste wenn kein Angriff modelliert (risikoarme Regel).
    """
    return RULE_OWASP_MAPPING.get(rule_id, [])


def get_owasp_label(category_id: str) -> str:
    """
    Gibt den lesbaren Namen einer OWASP-Kategorie zurück.

    Args:
        category_id: z. B. "LLM01"

    Returns:
        Kategorie-Name oder "Unknown" wenn nicht gefunden.
    """
    return OWASP_CATEGORIES.get(category_id, "Unknown")


def get_compliance_report(rule_ids: list[str]) -> dict:
    """
    Erstellt einen Compliance-Report für eine Liste aktiver Policy-Regeln.

    Zeigt welche OWASP LLM Top 10 Kategorien abgedeckt sind und berechnet
    den Coverage-Prozentsatz über alle gate-relevanten Kategorien.

    Args:
        rule_ids: Liste aktiver Rule-IDs (z. B. aus matched_rule_ids)

    Returns:
        {
          "covered_categories":        alle abgedeckten OWASP-IDs,
          "gate_relevant_categories":  gate-adressierbare OWASP-IDs,
          "gate_relevant_covered":     Schnittmenge,
          "coverage_pct":              Prozentsatz (0–100),
        }
    """
    covered: set[str] = set()
    for rule_id in rule_ids:
        covered.update(RULE_OWASP_MAPPING.get(rule_id, []))

    gate_relevant_covered = covered & GATE_RELEVANT_CATEGORIES
    coverage_pct = round(
        len(gate_relevant_covered) / max(len(GATE_RELEVANT_CATEGORIES), 1) * 100
    )

    return {
        "covered_categories":         sorted(covered),
        "gate_relevant_categories":   sorted(GATE_RELEVANT_CATEGORIES),
        "gate_relevant_covered":      sorted(gate_relevant_covered),
        "coverage_pct":               coverage_pct,
    }
