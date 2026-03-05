# CLAUDE.md – ImmuneGate Projektbeschreibung

Du bist Lead Developer für **ImmuneGate** – ein Security & Trust Layer für KI-Agenten.
Lies diese Datei vollständig bevor du irgendetwas baust oder änderst.

---

## Was ist ImmuneGate?

Ein Python-Package das wie ein Immunsystem zwischen KI-Agenten und ihren Tools sitzt.
Jede Tool-Aktion (Dateien, E-Mail, Web) läuft durch das Gate bevor sie ausgeführt wird.
Entscheidung: **ALLOW / ASK / DENY** – deterministisch, auditierbar, kein LLM inside.

**Die Kernaussage in einem Satz:**
`ig = ImmuneGate(config="kunde.yaml")` → `ig.activate()` → kein Bypass mehr möglich.

**GitHub Repository:**
`https://github.com/u6637434908-source/immunegate`

---

## Projektstruktur (aktueller Stand)

```
immunegate/
├── demo.py                           ← Golden Path Demo
├── demo_interaktiv.py                ← Interaktive Präsentations-Demo (Menü)
├── test_immunegate.py                ← 36 Unit Tests – müssen immer grün sein
├── immunegate.config.yaml            ← Standard-Kundenkonfiguration
├── immunegate.config.arztpraxis.yaml ← Beispiel-Kundenkonfiguration
├── szenario_webdesign.py             ← Testszenario Webdesign Agentur
├── szenario_arztpraxis.py            ← Testszenario Arztpraxis
├── szenario_steuerberater.py         ← Testszenario Steuerberater
├── szenario_schule.py                ← Testszenario Schule
├── szenario_onlineshop.py            ← Testszenario Online-Shop
├── ui/
│   ├── approval.html                 ← Approval UI (Risk Score, Badges, Preview)
│   └── scoreboard.html              ← Session Scoreboard (Donut Chart, PDF Export)
└── immunegate/
    ├── __init__.py
    ├── schemas.py                    ← Alle Datenmodelle
    ├── danger_signals.py             ← Regex-Erkennung (EN + DE Patterns)
    ├── risk_engine.py                ← Deterministischer Score
    ├── policy_engine.py              ← 13 Regeln (PRR-001 bis OBS-001)
    ├── gate.py                       ← Zentraler Entscheidungspunkt
    ├── audit.py                      ← Flight Recorder (JSON Export)
    ├── config.py                     ← YAML-Config Loader ← NEU
    ├── interceptor.py                ← Monkey-Patching Layer ← NEU
    └── wrapper.py                    ← ImmuneGate Hauptklasse
```

---

## Was bereits fertig ist (NICHT ANFASSEN)

**Sprint 1** – Core Engine: 13 Policy-Regeln, Risk Scoring, Audit Log, Fail-Safe Defaults
**Sprint 2** – UI: approval.html, scoreboard.html mit PDF Export
**Sprint 3** – Behavior Signals: BURST_RISK, NEW_EXTERNAL_TARGET
**Sprint 4** – Config + Interceptor: YAML-Config pro Kunde, Monkey-Patching Layer
**Tests** – 36 Unit Tests (alle grün), 5 Kundenszenarien, interaktive Demo

---

## Immer zuerst testen!

```bash
python demo.py
python test_immunegate.py
```

Wenn Tests nicht grün → nichts committen!

---

## Git Workflow

```bash
git add .
git commit -m "Kurze Beschreibung"
git push
```

---

## Nächste Schritte – Stufe 2: Open Source (Sprint 5)

**Priorität 1: Danger Signals erweitern**
Datei: `immunegate/danger_signals.py`
- Englisch: alle 5 Kategorien vervollständigen
- Deutsch: alle 5 Kategorien (STEALTH bereits drin)
- Französisch + Spanisch: Basis-Patterns für INJ_OVERRIDE + CREDENTIALS

**Priorität 2: PyPI Package vorbereiten**
- `pyproject.toml` erstellen
- Ziel: `pip install immunegate` funktioniert

**Priorität 3: Dokumentation**
- `docs/getting_started.md`
- `docs/config_reference.md`
- `docs/policy_rules.md`

**Priorität 4: Semantische Danger Signals** (nur nach 1-3)
- sentence-transformers für semantische Ähnlichkeit zusätzlich zu Regex

---

## Stufe 3 – Produkt (danach)

- Plugin-System für eigene Regeln
- Demo-App im Browser (live Gate-Entscheidungen)
- Pricing: Open Core (Basis kostenlos, Enterprise kostenpflichtig)
- Erste Pilotkunden in der Region Hallertau/München

---

## Arbeitsregeln (NICHT VERHANDELBAR)

1. Fail-Safe bleibt immer: Bei Fehler → DENY, nie ALLOW
2. Kein Bypass: 100% der Toolcalls durch das Gate
3. Deterministisch: Keine LLM-Aufrufe in Gate-Logik
4. Tests immer grün nach jeder Änderung
5. Einen Schritt nach dem anderen – Ergebnis zeigen bevor weiter
6. Git nach jedem Sprint: commit + push

---

## Policy Precedence

```
DENY > ALLOW > ASK > Score Fallback (0-39 ALLOW, 40-69 ASK, 70-100 DENY)
```
