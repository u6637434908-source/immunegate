# ImmuneGate – Masterindex

> Navigationszentrale für alle Projektbeteiligten.
> Wird von Claude Code zu Beginn jeder Session geprüft.

---

## Quick Links

| Bereich | Datei | Beschreibung |
|---------|-------|--------------|
| System-Kontext | [[CLAUDE.md]] | Arbeitsregeln, Sprints, Roadmap |
| Core Package | [[immunegate/]] | Python-Package |
| Tests | [[test_immunegate.py]] | 47 Unit Tests – immer grün |
| Beispiele | [[examples/]] | Demo + 5 Kundenszenarien |
| UI | [[ui/]] | Approval UI + Scoreboard + Demo App |
| Dokumentation | [[docs/]] | Getting Started, Config, Policy Rules |
| Berichte | [[99_Berichte/]] | Sprint-Berichte |
| Konfiguration | [[immunegate.config.yaml]] | Standard-Config |

---

## Projektübersicht

| Feld | Inhalt |
|------|--------|
| **Name** | ImmuneGate |
| **Tagline** | Das Immunsystem für KI-Agenten |
| **Status** | Stufe 2 abgeschlossen – Optimierung läuft |
| **GitHub** | https://github.com/u6637434908-source/immunegate |
| **Demo** | https://u6637434908-source.github.io/immunegate/ui/demo_app.html |
| **Author** | Bettina Mayerhofer |
| **Lizenz** | MIT |
| **Tests** | 47/47 grün |

---

## Sprint-Übersicht

| Sprint | Inhalt | Status |
|--------|--------|--------|
| Sprint 1 | Core Engine (13 Regeln, Risk Score, Audit) | ✅ |
| Sprint 2 | Approval UI + Scoreboard mit PDF Export | ✅ |
| Sprint 3 | Behavior Signals (BURST_RISK, NEW_EXTERNAL_TARGET) | ✅ |
| Sprint 4 | YAML-Config + Monkey-Patching Interceptor | ✅ |
| Sprint 5 | Danger Signals multilingual + PyPI + Docs | ✅ |
| Sprint 6 | Semantische Danger Signals (sentence-transformers) | ✅ |
| Sprint 7 | Plugin-System für eigene Kunden-Regeln | ✅ |
| Sprint 8 | Browser Demo-App (Plugin + Semantik + Scoreboard) | ✅ |
| Sprint 9 | Sicherheit & EU AI Act Compliance | ✅ |
| Sprint 10 | Entwickler-Erfahrung (CLI, Async, Logging) | 🔜 |
| Sprint 11 | Open Source Wachstum (GitHub Actions, Docs) | 🔜 |
| Sprint 12 | Mehr Interceptoren (subprocess, ftplib, paramiko) | 🔜 |

---

## Optimierungsplan (Priorität nach Rangfolge)

### 🥇 Sprint 9 – Sicherheit & EU AI Act Compliance
- Kryptografisch signierte Audit Logs (SHA-256 Hash-Kette)
- OWASP LLM Top 10 Mapping der 13 Policy-Regeln
- Tamper-Detection beim Laden der Config-Datei
- `__version__` in `__init__.py`

### 🥈 Sprint 10 – Entwickler-Erfahrung
- CLI-Tool: `immunegate check "delete /projects/"`
- Python `logging` statt Print-Ausgaben
- Async-Support für moderne Agenten-Frameworks
- Type Hints überall vervollständigen

### 🥉 Sprint 11 – Open Source Wachstum
- GitHub Actions – automatische Tests bei jedem Push
- Code Coverage Badge im README
- Contributing Guide für externe Entwickler
- Roadmap auf GitHub öffentlich als Issues

### Sprint 12 – Mehr Interceptoren
- `subprocess` abfangen (Living-off-the-land Angriffe)
- `ftplib` und `paramiko` (SSH) abfangen
- Rate-Limiting auf Gate-Ebene

---

## Aktueller Status

- **Letzte Aktualisierung:** 2026-03-07
- **Nächster Meilenstein:** Sprint 10 – Entwickler-Erfahrung (CLI, Logging, Async)
- **Tests:** 58/58 grün
- **GitHub Pages:** Live ✅
- **Präsentation:** Termin noch offen – Deep Research vorbereitet

---

## Verwandte Dokumente

- [[CLAUDE.md]] – Arbeitsregeln und Sprint-Planung
- [[docs/getting_started.md]] – Quickstart für neue Nutzer
- [[docs/policy_rules.md]] – Alle 13 Regeln erklärt
- [[99_Berichte/_Index.md]] – Alle Sprint-Berichte
