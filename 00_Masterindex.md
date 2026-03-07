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
| Plugins | [[plugins/]] | Beispiel-Plugins (no_sunday_deletes, hallertau) |
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
| **Status** | Stufe 2 abgeschlossen – Open Source ready |
| **GitHub** | https://github.com/u6637434908-source/immunegate |
| **Demo** | https://u6637434908-source.github.io/immunegate/ui/demo_app.html |
| **Author** | Bettina Mayerhofer |
| **Lizenz** | MIT |

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
| Sprint 7 | Plugin-System für eigene Regeln | ✅ |
| Sprint 8 | Demo-App Browser (live Gate-Entscheidungen) | 🔜 |

---

## Aktueller Status

- **Letzte Aktualisierung:** 2026-03-07
- **Nächster Meilenstein:** Sprint 8 – Demo-App Browser
- **Tests:** 47/47 grün
- **GitHub Pages:** Live ✅
