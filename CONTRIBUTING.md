# Contributing to ImmuneGate

Danke für dein Interesse an ImmuneGate! Contributions sind willkommen –
von Bug-Fixes über neue Danger Signals bis hin zu Plugin-Beispielen.

---

## Inhaltsverzeichnis

1. [Schnellstart](#schnellstart)
2. [Entwicklungsumgebung](#entwicklungsumgebung)
3. [Tests ausführen](#tests-ausführen)
4. [Code-Stil](#code-stil)
5. [Was kann ich beitragen?](#was-kann-ich-beitragen)
6. [Plugins schreiben](#plugins-schreiben)
7. [Neue Danger Signals](#neue-danger-signals)
8. [Pull Request Prozess](#pull-request-prozess)
9. [Sicherheitshinweise](#sicherheitshinweise)

---

## Schnellstart

```bash
# 1. Fork + Clone
git clone https://github.com/DEIN_USERNAME/immunegate.git
cd immunegate

# 2. Tests ausführen – müssen grün sein
python3 test_immunegate.py

# 3. Feature-Branch erstellen
git checkout -b feature/mein-feature

# 4. Änderungen + Tests
# ...

# 5. PR erstellen
git push origin feature/mein-feature
# → GitHub PR öffnen
```

---

## Entwicklungsumgebung

**Voraussetzungen:**
- Python 3.9 oder neuer
- Git

**Keine externen Pflichtabhängigkeiten** – ImmuneGate verwendet nur die Python-Standardbibliothek.

**Optionale Entwicklungswerkzeuge:**

```bash
pip install coverage          # Test-Coverage messen
pip install pyyaml            # Robusteres YAML-Parsing (optional)
pip install sentence-transformers  # Semantische Danger Signals (optional)
```

---

## Tests ausführen

ImmuneGate hat einen eigenen Test-Runner (kein pytest):

```bash
# Alle Tests ausführen
python3 test_immunegate.py

# Erwartete Ausgabe:
# Ergebnis: 66 bestanden, 0 fehlgeschlagen
# Alle Tests gruen!
```

**Coverage messen:**

```bash
python3 -m coverage run --source=immunegate test_immunegate.py
python3 -m coverage report --include="immunegate/*"
```

**Regel:** Kein Commit wenn Tests rot sind. Die GitHub Actions CI prüft automatisch
bei jedem Push (Python 3.9, 3.10, 3.11, 3.12).

---

## Code-Stil

- **Python 3.9+ kompatibel** – kein `dict | None` (→ `Optional[dict]`), aber
  `from __future__ import annotations` erlaubt neuere Syntax in Type Hints
- **Keine externen Abhängigkeiten** im Core (`immunegate/`) – nur Standardbibliothek
- **Deterministisch** – keine LLM-Aufrufe oder zufälligen Prozesse in Gate-Logik
- **Fail-Safe** – jeder Fehler muss zu DENY führen, nie zu ALLOW
- **Type Hints** – neue Funktionen vollständig mit Typen annotieren
- **Docstrings** – öffentliche Funktionen/Klassen brauchen eine kurze Beschreibung
- **Logging** statt `print()` für operative Ausgaben (außer interaktive Prompts)

```python
# ✅ Gut
import logging
logger = logging.getLogger("immunegate.mein_modul")

def meine_funktion(wert: str) -> Optional[str]:
    """Kurze Beschreibung was die Funktion tut."""
    try:
        result = _compute(wert)
        logger.info("Ergebnis: %s", result)
        return result
    except Exception as e:
        logger.warning("Fehler: %s → Fail-Safe", e)
        return None  # Fail-Safe

# ❌ Nicht
def meine_funktion(wert):
    print(f"Ergebnis: {_compute(wert)}")
    return _compute(wert)
```

---

## Was kann ich beitragen?

### Einfach (gut für Einstieg)

- **Neue Danger Signal Patterns** (weitere Sprachen, neue Angriffsvektoren)
- **Dokumentation** verbessern oder übersetzen
- **Bug-Fixes** – Issues mit `bug` Label
- **Tests** für noch nicht abgedeckte Pfade hinzufügen

### Mittel

- **Neue Beispiel-Plugins** in `plugins/` (z.B. Branchen-Regeln)
- **Config-Templates** für neue Branchen (`immunegate.config.*.yaml`)
- **CLI-Erweiterungen** in `immunegate/cli.py`
- **Interceptor-Module** für neue Python-Libraries

### Komplex (bitte zuerst Issue öffnen)

- **Neue Policy-Regeln** – betrifft alle Nutzer, sorgfältige Abwägung nötig
- **Neue Score-Parameter** – ändert Verhalten aller bestehenden Configs
- **Semantische Detection** verbessern – braucht Benchmark-Datensatz

---

## Plugins schreiben

Das einfachste Einstiegsfeld: ein eigenes Plugin für spezifische Regeln.

```python
# plugins/mein_plugin.py
from immunegate.plugins import BasePlugin
from immunegate.policy_engine import PolicyMatch
from immunegate.schemas import Action, Verb, Destination, Decision
from typing import Optional


class MeinPlugin(BasePlugin):
    """Beschreibung: Was macht dieses Plugin?"""

    @property
    def plugin_id(self) -> str:
        return "PLUGIN-MEIN-PLUGIN"

    def evaluate(self, action: Action) -> Optional[PolicyMatch]:
        # Gibt None zurück wenn das Plugin nicht zuständig ist
        if action.verb != Verb.SEND:
            return None

        # Eigene Logik...
        if "gefährlich" in action.target:
            return PolicyMatch(
                rule_id  = self.plugin_id,
                decision = Decision.DENY,
                reason   = "Gefährliches Ziel erkannt",
            )

        return None
```

**Regeln für Plugins:**
- `evaluate()` gibt `None` zurück wenn das Plugin nicht zuständig ist
- Exceptions werden ignoriert (Fail-Safe) – das Gate läuft weiter
- Plugin-DENY schlägt immer · Plugin-ALLOW schlägt Core-ASK
- Core-DENY schlägt immer Plugin-ALLOW (DENY > ALLOW > ASK)

**Plugin testen:**

```python
# In test_immunegate.py oder eigenem Test
from plugins.mein_plugin import MeinPlugin
from immunegate.schemas import Action, Verb, Tool, Destination, SourceTrust

plugin = MeinPlugin()
action = Action(verb=Verb.SEND, tool=Tool.EMAIL,
                destination=Destination.EXTERNAL, target="test@gefährlich.com",
                source_trust=SourceTrust.USER_DIRECT)
result = plugin.evaluate(action)
assert result is not None
assert result.decision.value == "DENY"
```

---

## Neue Danger Signals

Neue Erkennungsmuster gehören in `immunegate/danger_signals.py`:

```python
# In DANGER_PATTERNS (Regex-basiert)
DANGER_PATTERNS: dict[DangerSignal, list[str]] = {
    DangerSignal.STEALTH: [
        # Bestehende Pattern...
        r"mein_neues_muster",   # ← hier hinzufügen
    ],
}
```

**Anforderungen:**
- Präzision vor Recall – lieber zu wenig als zu viele False Positives
- Jedes neue Pattern braucht einen Test
- Sprachfamilien: DE + EN + FR + ES – gerne weitere hinzufügen
- Pattern muss case-insensitive sein (`re.IGNORECASE`)

---

## Pull Request Prozess

1. **Issue öffnen** (bei größeren Änderungen) – Konzept abstimmen
2. **Fork + Feature-Branch** – nie direkt auf `main` pushen
3. **Tests grün** – `python3 test_immunegate.py` muss 100% bestehen
4. **Für neue Features: Tests hinzufügen** – Coverage soll gleich bleiben oder steigen
5. **PR mit Beschreibung** erstellen:
   - Was wurde geändert?
   - Warum?
   - Welche Tests wurden hinzugefügt?
6. **Review** – mindestens ein Approval nötig
7. **Merge** – Squash-Merge auf main

**PR Titel-Format:**

```
feat: Neue DangerSignal-Pattern für Portugiesisch
fix: PRR-004 false positive bei read_sensitive
docs: Plugin-Entwickler-Guide erweitern
test: Coverage für interceptor.py erhöhen
```

---

## Sicherheitshinweise

ImmuneGate ist ein Sicherheits-Tool – entsprechend gelten strenge Regeln:

**Niemals:**
- Fail-Safe-Logik entfernen (jeder Fehler → DENY)
- LLM-Aufrufe in der Gate-Entscheidungslogik hinzufügen
- Policy-Regeln lockern ohne Sicherheitsbegründung
- External Dependencies ohne Begründung hinzufügen (Angriffsfläche)

**Sicherheitslücken melden:**

Bitte **nicht** als öffentliches Issue – stattdessen direkt an:
`security@immunegate.dev` (oder als Private Vulnerability Report auf GitHub)

---

## Fragen?

- GitHub Discussions für allgemeine Fragen
- Issues für Bugs und Feature-Requests
- Der Code ist der beste Einstieg – besonders `immunegate/gate.py` und `immunegate/policy_engine.py`

Danke für deinen Beitrag! 🛡️
