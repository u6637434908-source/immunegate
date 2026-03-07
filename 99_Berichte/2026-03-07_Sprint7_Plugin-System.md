# Bericht: Sprint 7 – Plugin-System
**Datum:** 2026-03-07 | **Typ:** Coding

---

## Ausgeführte Arbeit

Implementierung eines vollständigen Plugin-Systems für ImmuneGate. Kunden können
ab sofort eigene Policy-Regeln als externe Python-Klassen hinzufügen, ohne den
Core-Code anzufassen.

---

## Ergebnisse

### Neue Dateien

| Datei | Inhalt |
|-------|--------|
| `immunegate/plugins.py` | `BasePlugin` ABC, `load_plugins()`, `run_plugins()` |
| `plugins/no_sunday_deletes.py` | Beispiel: DELETE am Sonntag → ASK |
| `plugins/hallertau_allowlist.py` | Beispiel: Bayerische Regional-Domains → ALLOW |

### Geänderte Dateien

| Datei | Änderung |
|-------|---------|
| `immunegate/gate.py` | `__init__` nimmt `plugins`-Parameter, `_evaluate_safe` ruft `run_plugins()` auf |
| `immunegate/wrapper.py` | `ImmuneGate.__init__` nimmt `plugins`-Parameter, lädt Plugins via `load_plugins()` |
| `test_immunegate.py` | 11 neue Plugin-Tests hinzugefügt |

### Architektur-Entscheidungen

**Ausführungsreihenfolge:**
```
Core-Regeln (PRR/TOL) → Plugin-Regeln → apply_precedence(alle Matches)
```

**Precedence:** Global `DENY > ALLOW > ASK` – egal ob Core oder Plugin.
Damit ist Core-DENY strukturell unüberwindbar (kein Plugin kann DENY aufheben).

**Fail-Safe:** Defekte Plugin-Dateien beim Import → überspringen.
Exceptions in `evaluate()` → ignorieren. Gate läuft immer weiter.

**Interface:**
```python
ig = ImmuneGate(config="kunde.yaml", plugins="plugins/")
```
Plugins werden beim Start geladen und geloggt:
```
[ImmuneGate] Plugins geladen: 2 (PLUGIN-HALLERTAU-ALLOWLIST, PLUGIN-NO-SUNDAY-DELETE)
```

### Beispiel-Plugin-Verhalten

**`hallertau_allowlist.py`** – ALLOW schlägt Core-ASK (TOL-003):
```
send → reiterhof-ried.de  (USER_DIRECT, extern)
Core:   TOL-003 → ASK
Plugin: PLUGIN-HALLERTAU-ALLOWLIST → ALLOW
Gesamt: ALLOW (ALLOW > ASK)
```

**Core-DENY schlägt Plugin-ALLOW:**
```
send → reiterhof-ried.de  (WEB-Source, extern)
Core:   PRR-003 → DENY
Plugin: PLUGIN-HALLERTAU-ALLOWLIST → ALLOW
Gesamt: DENY (DENY > ALLOW) ← Core gewinnt ✅
```

---

## Tests (vorher/nachher)

| | Tests |
|-|-------|
| Vorher | 36 bestanden, 0 fehlgeschlagen |
| Nachher | **47 bestanden, 0 fehlgeschlagen** |

### Neue Tests (11 Stück)

| Test | Was geprüft wird |
|------|-----------------|
| `test_plugin_hallertau_known_domain` | ALLOW für `reiterhof-ried.de` |
| `test_plugin_hallertau_unknown_domain` | None für unbekannte Domain |
| `test_plugin_no_sunday_non_sunday` | None wenn kein Sonntag |
| `test_plugin_no_sunday_read_always_none` | READ → immer None |
| `test_plugin_load_from_directory` | Beide Plugins aus `plugins/` geladen |
| `test_plugin_fail_safe_broken_plugin` | Crash → leere Liste, kein Gate-Absturz |
| `test_plugin_fail_safe_empty_dir` | Leeres Verzeichnis → `[]` |
| `test_plugin_fail_safe_nonexistent_dir` | Nicht-existent → `[]` |
| `test_plugin_integrated_in_gate_allow` | Plugin-ALLOW schlägt Core-ASK |
| `test_plugin_core_deny_beats_plugin_allow` | Core-DENY schlägt Plugin-ALLOW |
| `test_plugin_immunegate_wrapper_loads_plugins` | Wrapper lädt Plugins korrekt |

---

## Erstellte Dokumente

- `immunegate/plugins.py`
- `plugins/no_sunday_deletes.py`
- `plugins/hallertau_allowlist.py`
- `99_Berichte/2026-03-07_Sprint7_Plugin-System.md` (diese Datei)

---

## Offene Punkte

- Dokumentation: `docs/plugin_development.md` für Kunden-Entwickler (Sprint 8)
- Config-gesteuerte Plugin-Aktivierung via `immunegate.config.yaml`
- Plugin-Versionierung und Kompatibilitätsprüfung
