# ImmuneGate

**Das Immunsystem für KI-Agenten.**

ImmuneGate ist ein deterministischer Security & Trust Layer, der zwischen KI-Agenten und ihren Tools sitzt. Jede Tool-Aktion – Dateizugriff, E-Mail, Web-Browsing – läuft durch das Gate, bevor sie ausgeführt wird. Die Entscheidung (ALLOW / ASK / DENY) ist regelbasiert, auditierbar und funktioniert ohne LLM-Aufrufe.

```
KI-Agent → ig.files.delete("/projects/") → [ImmuneGate] → DENY
```

---

## Warum ImmuneGate?

KI-Agenten handeln eigenständig – sie lesen, schreiben, löschen und versenden. Bestehende Systeme vergeben dabei pauschale Berechtigungen ohne Rücksicht auf Kontext oder Herkunft der Anweisung. Ein einziger vergifteter Input reicht aus um einen Agenten umzulenken.

ImmuneGate sitzt als unabhängiger Layer zwischen Agent und Tools – plattformunabhängig, ohne LLM-Aufrufe in der Entscheidungslogik, und mit vollständiger Nachvollziehbarkeit. Damit alle gesund bleiben.

---

## Voraussetzungen

- Python 3.9 oder neuer
- Node.js + npx (für die Approval UI)

Keine weiteren Abhängigkeiten – ImmuneGate verwendet ausschließlich die Python-Standardbibliothek.

---

## Installation

```bash
# Repository klonen oder entpacken
cd Immungate

# Kein pip-Install nötig – demo.py setzt den Pfad automatisch
python3 demo.py
```

---

## Demo starten

```bash
python3 demo.py
```

Die Demo zeigt den **Golden Path** – einen vollständigen Prompt-Injection-Angriff und wie ImmuneGate ihn abwehrt:

| Schritt | Aktion | Entscheidung | Regel |
|---------|--------|--------------|-------|
| 1 | Dateien lesen, Web browsen | ✅ ALLOW | PRR-005 |
| 2 | Vergiftete E-Mail eingeht | — (Session markiert als kontaminiert) | — |
| 3 | Agent versucht `/projects/` zu löschen | 🛑 DENY | PRR-007 (MASS_DESTRUCT) |
| 4 | Agent versucht Mail an `attacker@gmail.com` | 🛑 DENY | PRR-003 |
| 5 | Delete in Sandbox `/tmp/demo_sandbox/` | ✅ ALLOW | TOL-002 |
| 6 | Interne Mail an `colleague@company.com` | ✅ ALLOW | TOL-001 |

Am Ende wird ein Audit-Log unter `/tmp/immunegate_demo_audit.json` gespeichert.

---

## UI starten (Approval & Scoreboard)

```bash
npx serve ui -l 7890 --no-clipboard
```

Alle UIs sind dann unter `http://localhost:7890/` erreichbar:

### Approval UI — `approval.html`

Bei ASK-Entscheidungen aufgerufen. Zeigt Risk Score, Score Breakdown, Gründe, Regelmatches, Danger Signals und eine kontextabhängige Vorschau der Aktion – mit **Genehmigen** / **Ablehnen** Buttons.

```
http://localhost:7890/approval.html
```

Daten per URL-Parameter übergeben: `?data=BASE64` oder `?file=URL`. Demo-Daten werden automatisch geladen wenn kein Parameter gesetzt ist.

### Session Scoreboard — `scoreboard.html`

Visualisiert den Audit-Log einer kompletten Session:

- **ALLOW / ASK / DENY Verteilung** als Donut-Chart
- **4 KPI-Kacheln**: Aktionen gesamt, Deny Rate, Untrusted Influence Rate, Approval Rate
- **Top 3 ausgelöste Regeln** als Horizontal-Balken
- **Event-Timeline** (letzte 20 Events, neueste zuerst) mit Danger-Signal-Badges und Kontaminations-Markierung

```
http://localhost:7890/scoreboard.html
```

Audit-Log laden über den **📂 Datei-Picker** direkt im Browser (kein Server-Upload nötig).

#### PDF Export

Der **📄 PDF Export**-Button generiert einen vollständigen **Security Incident Report**:

- Cover mit Session-ID, Policy-Version, VERTRAULICH-Badge
- Executive Summary (Metriken)
- Entscheidungs-Timeline als Tabelle (kontaminierte Zeilen gelb hinterlegt)
- Erkannte Danger Signals
- Top ausgelöste Regeln
- Vollständige Session Metriken

Mit der **🔒 PII schwärzen**-Checkbox werden E-Mail-Adressen im Report geschwärzt (`attacker@gmail.com` → `[GESCHWÄRZT]@gmail.com`).

---

## Architektur

```
immunegate/
├── __init__.py          ← Öffentlicher Export: ImmuneGate
├── wrapper.py           ← ImmuneGate-Klasse (Einzeiler-API für Agenten)
│                           sub-wrappers: .files  .email  .web
│                           Behavior Detection: BURST_RISK, NEW_EXTERNAL_TARGET
├── gate.py              ← PermissionGate – zentraler Entscheidungspunkt
│                           Preview-Generierung (delete/send/write)
│                           Dry-Run-Scan vor jedem delete
│                           Fail-Safe: jeder Fehler → DENY
├── policy_engine.py     ← 13 Regeltypen (PRR / TOL / OBS)
│                           Precedence: DENY > ALLOW > ASK
├── risk_engine.py       ← Deterministischer Risk Score (0–100)
│                           impact + trust_modifier + danger_sum + behavior_bonus
├── danger_signals.py    ← Regex-Erkennung: INJ_OVERRIDE, MASS_DESTRUCT, STEALTH …
├── schemas.py           ← Alle Datenmodelle: Action, Decision, Verb, GateResult …
└── audit.py             ← Flight Recorder – strukturiertes JSON-Audit-Log

ui/
├── approval.html        ← Approval UI: ASK-Entscheidungen bestätigen/ablehnen
└── scoreboard.html      ← Session Scoreboard: Audit-Log visualisieren + PDF Export

demo.py                  ← Golden Path Demo
test_immunegate.py       ← 36 Unit Tests (python3 test_immunegate.py)
```

### Entscheidungsfluss

```
ig.files.delete("/projects/")
        │
        ▼
  _detect_behavior_flags()   ← BURST_RISK? NEW_EXTERNAL_TARGET?
        │
        ▼
  calculate_score()          ← impact + trust_modifier + danger_sum + behavior_bonus
        │
        ▼
  evaluate_policies()        ← Regelprüfung (PRR-001 … TOL-003)
        │
        ▼
  apply_precedence()         ← DENY > ALLOW > ASK
        │
        ▼
  _build_preview_spec()      ← Dry-Run Scan / Subject+Body / Datei-Diff
        │
        ▼
  ALLOW / ASK / DENY         ← Audit Log + Ausgabe
```

### Sicherheitsprinzipien

- **Fail-Safe:** Jeder interne Fehler führt zu DENY – das Gate schlägt nie offen fehl.
- **Kein Bypass:** 100 % aller Tool-Aufrufe laufen durch das Gate.
- **Deterministisch:** Keine LLM-Aufrufe in der Gate-Logik – reproduzierbar und auditierbar.
- **Contamination Tagging:** Untrusted Input (Web, externe Mail) markiert die gesamte Session als kontaminiert. Folgeaktionen erhalten erhöhten Risk Score.
- **Preview Safety:** ASK wird nur angezeigt, wenn eine Preview generiert werden kann – andernfalls DENY.

---

## Kurzreferenz API

```python
from immunegate import ImmuneGate
from immunegate.schemas import SourceTrust

ig = ImmuneGate(session_id="my-agent-001")

# Externe Eingabe registrieren (setzt Contamination Tag)
ig.receive_input(email_body, SourceTrust.EMAIL_EXTERNAL)

# Tool-Aktionen – Gate entscheidet automatisch
ig.files.read("/data/report.pdf")          # → ALLOW
ig.files.write("/data/output.txt", "...")  # → ASK wenn kontaminiert
ig.files.delete("/projects/")             # → DENY (MASS_DESTRUCT)
ig.email.send("user@company.com", "Betr", body="...")  # → ALLOW (intern)
ig.email.send("x@gmail.com", "Betr", body="...")       # → DENY / ASK
ig.web.browse("https://docs.python.org")  # → ALLOW

# Audit
ig.print_summary()
ig.export_audit("/tmp/audit.json")
```

### Risk Score

| Bereich | Entscheidung (Score Fallback) |
|---------|-------------------------------|
| 0 – 39  | ALLOW |
| 40 – 69 | ASK   |
| 70 – 100| DENY  |

Policy-Regeln haben Vorrang vor dem Score Fallback.

---

## Entstehung

Entwickelt von Bettina Mayerhofer im Rahmen des KOKIEU-Moduls 2026 (Konzeption KI gestützter Entwicklungsumgebungen) als Open-Source MVP. Feedback und Contributions sind willkommen.

---

## Contributing

Pull Requests sind willkommen – besonders für neue Danger Signal Patterns, zusätzliche Sprachen, und Tool-Integrationen. Bitte vorher ein Issue öffnen um größere Änderungen abzustimmen.

---

## Lizenz

MIT
