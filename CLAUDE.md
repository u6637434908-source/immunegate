# CLAUDE.md – ImmuneGate System Kontext

> Diese Datei wird zu Beginn JEDER Session vollständig gelesen.
> Kein Task ohne vorherige Lektüre dieser Datei.

---

## Projekt-Identität

**Name:** ImmuneGate  
**Ziel:** Security & Trust Layer für KI-Agenten – das Immunsystem für KI  
**Status:** Stufe 2 abgeschlossen – bereit für Stufe 3  
**GitHub:** `https://github.com/u6637434908-source/immunegate`  
**Autorin:** Bettina Mayerhofer  
**Policy Version:** v1.0  

**Die Kernaussage:**
`ig = ImmuneGate(config="kunde.yaml")` → `ig.activate()` → kein Bypass mehr möglich.

---

## Meine Rolle als Claude Code

Ich bin Lead Developer für ImmuneGate. Meine Verantwortlichkeiten:
- Code schreiben der den Arbeitsregeln entspricht
- Tests nach jeder Änderung ausführen
- Bericht nach jedem Sprint in `99_Berichte/` ablegen
- Masterindex aktualisieren
- Nie committen wenn Tests rot sind

---

## Session-Start Checkliste (PFLICHT)

Vor jedem Task diese Schritte ausführen:

```bash
# 1. Änderungs-Detection – was hat sich geändert?
find . -name "*.py" -newer CLAUDE.md -not -path "./.git/*"

# 2. Tests ausführen – sind wir noch grün?
python3 test_immunegate.py

# 3. Git Status – was ist uncommitted?
git status
```

Erst wenn alle drei Checks grün sind → mit dem Task beginnen.

---

## Projektstruktur (aktueller Stand)

```
Immungate/
├── CLAUDE.md                             ← System-Kontext (diese Datei)
├── 00_Masterindex.md                     ← Navigation & Links
├── immunegate/                           ← Core Package
│   ├── __init__.py
│   ├── schemas.py
│   ├── danger_signals.py                 ← Regex EN/DE/FR/ES
│   ├── risk_engine.py
│   ├── policy_engine.py                  ← 13 Regeln
│   ├── gate.py
│   ├── audit.py
│   ├── config.py                         ← YAML-Config Loader
│   ├── interceptor.py                    ← Monkey-Patching Layer
│   └── wrapper.py
├── ui/                                   ← Web Apps
│   ├── approval.html
│   ├── scoreboard.html
│   └── demo_app.html
├── examples/                             ← Demos & Szenarien
├── docs/                                 ← Dokumentation
│   ├── getting_started.md
│   ├── config_reference.md
│   └── policy_rules.md
├── 99_Berichte/                          ← Sprint-Berichte
│   └── _Index.md
├── test_immunegate.py
├── immunegate.config.yaml
├── immunegate.config.arztpraxis.yaml
├── pyproject.toml
├── README.md
└── LICENSE
```

---

## Was bereits fertig ist (NICHT ANFASSEN)

| Sprint | Inhalt | Status |
|--------|--------|--------|
| Sprint 1 | Core Engine: 13 Regeln, Risk Scoring, Audit Log, Fail-Safe | ✅ |
| Sprint 2 | UI: approval.html, scoreboard.html mit PDF Export | ✅ |
| Sprint 3 | Behavior Signals: BURST_RISK, NEW_EXTERNAL_TARGET | ✅ |
| Sprint 4 | Config + Interceptor: YAML pro Kunde, Monkey-Patching | ✅ |
| Sprint 5 | Danger Signals DE/EN/FR/ES, PyPI, Dokumentation | ✅ |

---

## Nächste Schritte – Stufe 3: Produkt

**Sprint 6 – Plugin-System**
- Eigene Regeln als externe Python-Klassen einbinden
- `immunegate/plugins/` Ordner
- Beispiel-Plugin als Vorlage

**Sprint 7 – Demo-App Browser**
- Vollständige interaktive Web-App
- Live Gate-Entscheidungen im Browser

**Sprint 8 – Erste Pilotkunden**
- Config-Templates für Branchen
- Onboarding-Dokumentation
- Pricing: Open Core

---

## Immer zuerst testen!

```bash
python3 test_immunegate.py
```

Erwartung: 36 bestanden, 0 fehlgeschlagen
Wenn rot: Nichts committen – erst fixen!

---

## Git Workflow

```bash
git add .
git commit -m "Sprint X: Kurze Beschreibung"
git push
```

---

## Berichts-Pflicht (nach jedem Sprint)

Dateiname: `99_Berichte/YYYY-MM-DD_HH-MM_SprintX.md`

```markdown
# Bericht: Sprint X – [Titel]
**Datum:** YYYY-MM-DD | **Zeit:** HH:MM | **Typ:** Coding

## Ausgeführte Arbeit
## Ergebnisse  
## Tests (vorher/nachher)
## Erstellte/geänderte Dateien
## Offene Punkte
```

---

## Arbeitsregeln (NICHT VERHANDELBAR)

1. Fail-Safe: Bei Fehler → DENY, nie ALLOW
2. Kein Bypass: 100% der Toolcalls durch das Gate
3. Deterministisch: Keine LLM-Aufrufe in Gate-Logik
4. Tests grün: Nach jeder Änderung – rot = nicht committen
5. Schrittweise: Ergebnis zeigen bevor weiter
6. Bericht: Nach jedem Sprint in 99_Berichte/ dokumentieren
7. Masterindex: Nach jedem Sprint aktualisieren

---

## Policy Precedence

```
DENY > ALLOW > ASK > Score Fallback
Score: 0-39 ALLOW | 40-69 ASK | 70-100 DENY
```

---

## Änderungs-Detection (vor JEDER Aufgabe)

**Stufe 1 – Metadaten prüfen (schnell):**
```bash
stat -f "%Sm %N" -t "%Y-%m-%d %H:%M" *.md *.py
find . -name "*.py" -newer 99_Berichte/_Index.md
```

**Stufe 2 – Bei Fund → Inhalt laden:**
```bash
cat CLAUDE.md
cat 00_Masterindex.md
```

**Wann prüfen:**
- Vor JEDER Aufgabe
- Nach Pausen > 10 Minuten
- Bei Verdacht auf externe Änderungen

---

## Berichts-Pflicht (nach JEDER Aufgabe)

**Speicherort:** `99_Berichte/YYYY-MM-DD_SprintX_Taskname.md`

**Struktur:**
```markdown
# Bericht: [Taskname]
**Datum:** YYYY-MM-DD
**Typ:** Coding/Analyse/Debugging

## Ausgeführte Arbeit
## Ergebnisse
## Fehler & Debugging
## Erstellte Dokumente
## Verknüpfungen
```

**Danach:** `99_Berichte/_Index.md` aktualisieren!

---

## Session-Checkliste

### Vor jeder Aufgabe:
- [ ] `CLAUDE.md` gelesen
- [ ] `00_Masterindex.md` geprüft
- [ ] Änderungs-Detection durchgeführt
- [ ] `python3 test_immunegate.py` ausgeführt

### Nach jeder Aufgabe:
- [ ] Tests grün (36/36)
- [ ] Bericht erstellt in `99_Berichte/`
- [ ] `_Index.md` aktualisiert
- [ ] `00_Masterindex.md` aktualisiert
- [ ] `git add . && git commit && git push`
