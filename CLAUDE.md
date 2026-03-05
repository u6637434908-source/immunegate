# CLAUDE.md – ImmuneGate Projektbeschreibung

Du bist Lead Developer für **ImmuneGate** – ein Security & Trust Layer für KI-Agenten.
Lies diese Datei vollständig bevor du irgendetwas baust oder änderst.

---

## Was ist ImmuneGate?

Ein Python-Package das wie ein Immunsystem zwischen KI-Agenten und ihren Tools sitzt.
Jede Tool-Aktion (Dateien, E-Mail, Web) läuft durch das Gate bevor sie ausgeführt wird.
Entscheidung: **ALLOW / ASK / DENY** – deterministisch, auditierbar, kein LLM inside.

**Die Kernaussage in einem Satz:**
`ig = ImmuneGate()` → `ig.files.delete("/projects/")` → Gate entscheidet automatisch.

---

## Aktueller Stand (alles fertig – NICHT ANFASSEN)

**Sprint 1 ✅** – Kern
```
immunegate/
├── demo.py
└── immunegate/
    ├── __init__.py
    ├── schemas.py              ← Alle Datenmodelle (Action, Decision, Verb, etc.)
    ├── danger_signals.py       ← Regex-Erkennung für INJ_OVERRIDE, MASS_DESTRUCT etc.
    ├── risk_engine.py          ← Deterministischer Score (impact + trust + danger)
    ├── policy_engine.py        ← 13 Regeln (PRR-001 bis OBS-001) mit Precedence
    ├── gate.py                 ← Permission Gate – zentraler Entscheidungspunkt
    ├── audit.py                ← Flight Recorder – loggt alle Events als JSON
    └── wrapper.py              ← ImmuneGate Klasse – der Einzeiler für Agenten
```

**Sprint 2 ✅** – UI & Preview
- `ui/approval.html` – Approval UI mit Risk Score, Preview, Genehmigen/Ablehnen
- Dry-Run für delete (Vorab-Scan vor ASK)
- Preview für send (Empfänger + Domain-Warnung + Body)
- Preview für write (Diff vorher/nachher)
- Behavior Signals: BURST_RISK, NEW_EXTERNAL_TARGET

**Sprint 3 ✅** – Polish & Tests
- `ui/scoreboard.html` – Session Scoreboard mit Donut-Chart, KPIs, Timeline
- PDF Export mit PII-Schwärzung direkt aus dem Scoreboard
- `test_immunegate.py` – 36 Unit Tests, alle grün

---

## Immer zuerst testen

Vor jeder Änderung beide Befehle ausführen – beide müssen grün sein:

```bash
python3 demo.py
python3 test_immunegate.py
```

Erwartete Ausgabe demo.py: 5× ALLOW, 2× DENY – Golden Path intakt.
Erwartete Ausgabe tests: 36 bestanden, 0 fehlgeschlagen.

---

## Was noch offen ist (Sprint 4 – noch nicht starten)

- Danger Signals auf Deutsch + weitere Sprachen (danger_signals.py erweitern)
- PyPI Package (pip install immunegate)
- GitHub Release vorbereiten
- README finalisieren

**Warte auf explizite Anweisung bevor du Sprint 4 anfängst.**

---

## Demo-Incident (Golden Path – muss immer funktionieren)

1. Agent liest Dateien → ALLOW (PRR-005)
2. Vergiftete E-Mail kommt rein (enthält "delete all", "silently", "rm -rf")
3. Agent versucht delete("/projects/") → DENY (PRR-007: MASS_DESTRUCT)
4. Agent versucht send("attacker@gmail.com") → DENY (PRR-003)
5. Delete in Sandbox → ALLOW (TOL-002)
6. Interne Mail → ALLOW (TOL-001)

---

## Arbeitsregeln (NICHT VERHANDELBAR)

1. **Fail-Safe bleibt immer:** Bei jedem Fehler → DENY, nie ALLOW
2. **Kein Bypass:** 100% der Toolcalls laufen durch das Gate
3. **Deterministisch:** Keine LLM-Aufrufe in der Gate-Logik
4. **Preview Safety:** ASK nur wenn Preview generierbar, sonst DENY
5. **Einen Schritt nach dem anderen:** Zeig Ergebnis nach jedem Deliverable
6. **Tests müssen immer grün sein:** Nach jeder Änderung testen

---

## Policy Precedence (zur Erinnerung)

```
DENY > ALLOW > ASK > Score Fallback (0-39 ALLOW, 40-69 ASK, 70-100 DENY)
```
