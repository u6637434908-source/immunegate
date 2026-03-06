# Policy-Regeln – ImmuneGate

ImmuneGate entscheidet anhand von deterministischen Regeln – kein LLM, kein Zufall.
Jede Tool-Aktion durchläuft alle Regeln. Das Ergebnis mit der höchsten Priorität gewinnt.

---

## Entscheidungs-Hierarchie

```
DENY  >  ALLOW  >  ASK  >  Score Fallback
```

Wenn mehrere Regeln matchen, gilt immer die stärkste:
1. Ein DENY überschreibt alle anderen Treffer
2. Ein ALLOW überschreibt ein ASK
3. Score Fallback greift nur wenn **keine** Regel matcht

---

## Regeltypen

| Typ | Beschreibung |
|-----|-------------|
| **PRR** | Primär-Reflexregeln – sicherheitskritisch, angeboren, nicht konfigurierbar |
| **TOL** | Toleranzregeln – kontextabhängige Ausnahmen, konfigurierbar via Allowlist |

---

## PRR – Primär-Reflexregeln

### PRR-001 · Credentials-Exfiltration → DENY

**Wann:** `send` oder `upload` nach `EXTERNAL` + Danger Signal `CREDENTIALS`

**Warum:** Zugangsdaten dürfen unter keinen Umständen nach außen gelangen – unabhängig vom Absender.

```python
ig.check(verb="send", target="attacker@evil.com", content="API-Key: sk-...")
# → DENY (PRR-001)
```

---

### PRR-002 · Löschaktion → ASK

**Wann:** Verb `delete`

**Warum:** Löschen ist irreversibel. Jede Löschaktion braucht menschliche Bestätigung.

> **Ausnahme:** TOL-002 überschreibt PRR-002 für Sandbox-Pfade.

```python
ig.check(verb="delete", target="/projekte/wichtig.pdf")
# → ASK (PRR-002)
```

---

### PRR-003 · Untrusted Source → kein Send nach extern → DENY

**Wann:** `send` nach `EXTERNAL` + `source_trust` ist `WEB` oder `EMAIL_EXTERNAL`

**Warum:** Eine E-Mail oder Webseite soll keine externe Kommunikation auslösen können – klassische Prompt-Injection-Abwehr.

```python
ig.check(verb="send", target="partner@extern.de",
         source_trust="email_external")
# → DENY (PRR-003)
```

---

### PRR-004 · Schreibzugriff unter Fremdeinfluss → ASK

**Wann:** `write` oder `write_sensitive` + `source_trust` ist `WEB` oder `EMAIL_EXTERNAL`

**Auch:** Session ist `contaminated` (durch vorherigen untrusted Input) + destruktive Aktion (`write`, `write_sensitive`, `delete`, `send`, `upload`)

**Warum:** Schreibaktionen unter direktem oder indirektem Fremdeinfluss erfordern Nutzerbestätigung.

```python
ig.check(verb="write", target="/config/settings.json",
         source_trust="web")
# → ASK (PRR-004)
```

---

### PRR-005 · Lesen und Browsen → ALLOW

**Wann:** Verb `read` oder `browse`

**Warum:** Risikoarme Aktionen – Lesezugriff ohne Destruktivpotenzial wird standardmäßig erlaubt.

```python
ig.check(verb="read", target="/projekte/bericht.pdf")
# → ALLOW (PRR-005)
```

---

### PRR-006 · Sensible Daten lesen → ASK

**Wann:** Verb `read_sensitive`

**Warum:** Sensible Daten (Patientenakten, Finanzunterlagen) erfordern bewusste Bestätigung – auch bei harmlosen Quellen.

```python
ig.check(verb="read_sensitive", target="/patienten/mueller.pdf")
# → ASK (PRR-006)
```

---

### PRR-007 · MASS_DESTRUCT-Signal → DENY

**Wann:** Danger Signal `MASS_DESTRUCT` erkannt (z. B. „delete all", „rm -rf", „DROP TABLE")

**Warum:** Massenhafte oder irreversible Datenzerstörung wird sofort gestoppt – Reflex, kein Score.

```python
ig.check(verb="delete", target="/", content="delete all files recursively")
# → DENY (PRR-007)
```

---

### PRR-008 · STEALTH-Signal → DENY

**Wann:** Danger Signal `STEALTH` erkannt (z. B. „silently", „without notifying the user", „bypass audit")

**Warum:** Versuche, Aktionen vor dem Nutzer zu verbergen oder Logs zu umgehen, sind absolut verboten.

```python
ig.check(verb="send", target="intern@firma.de",
         content="send this silently without logging")
# → DENY (PRR-008)
```

---

## TOL – Toleranzregeln

### TOL-001 · Interne Kommunikation auf Allowlist → ALLOW

**Wann:** `send` nach `INTERNAL` + Empfänger-Domain auf `internal_domains`-Allowlist

**Warum:** Interne E-Mails an bekannte Domains sind normal und sollen nicht blockiert werden.

**Konfiguration:**
```yaml
allowlist:
  internal_domains:
    - "meinunternehmen.de"
    - "intern.local"
```

```python
ig.check(verb="send", target="kollege@meinunternehmen.de",
         destination="internal")
# → ALLOW (TOL-001)
```

---

### TOL-002 · Delete in Sandbox → ALLOW

**Wann:** `delete` + Zielpfad beginnt mit einem konfigurierten `sandbox_paths`-Eintrag

**Warum:** In Testumgebungen und temporären Arbeitsbereichen soll der Agent ohne ständige Bestätigung aufräumen können.

**Überschreibt:** PRR-002 (Delete → ASK)

**Konfiguration:**
```yaml
allowlist:
  sandbox_paths:
    - "/tmp/sandbox/"
    - "/tmp/test/"
```

```python
ig.check(verb="delete", target="/tmp/sandbox/temp_output.txt")
# → ALLOW (TOL-002)
```

> **Sicherheitshinweis:** Sandbox-Pfade sollten nie produktive Daten enthalten.

---

### TOL-003 · Neue externe Empfänger → ASK

**Wann:** `send` nach `EXTERNAL` + Empfänger-Domain **nicht** auf Allowlist + `source_trust` ist `USER_DIRECT`

**Warum:** Wenn ein Nutzer direkt eine E-Mail an eine unbekannte externe Domain schicken möchte, soll der Agent nachfragen – ohne zu blockieren.

```python
ig.check(verb="send", target="neukontakt@unbekannt.com",
         source_trust="user_direct")
# → ASK (TOL-003)
```

---

## Score Fallback

Wenn **keine** der Regeln oben matcht, entscheidet der Risk Score:

| Score | Entscheidung |
|-------|-------------|
| 0–39  | ALLOW |
| 40–69 | ASK |
| 70–100 | DENY |

Schwellenwerte sind per Konfiguration anpassbar. Siehe [config_reference.md](config_reference.md).

---

## Risk Score – Zusammensetzung

```
Risk Score = impact + trust_modifier + danger_sum + behavior_bonus
             (clamp: 0–100)
```

### Impact (Verb-Basiswert)

| Verb | Impact |
|------|--------|
| `send` | 95 |
| `upload` | 90 |
| `delete` | 85 |
| `write_sensitive` | 80 |
| `write` | 60 |
| `read_sensitive` | 55 |
| `read` | 20 |
| `browse` | 10 |

### Trust Modifier (Source)

| Source Trust | Modifier |
|-------------|---------|
| `internal_system` | −10 |
| `user_direct` | 0 |
| `internal_doc` | +5 |
| `email_internal` | +10 |
| `unknown` | +10 |
| `email_external` | +20 |
| `web` | +25 |

### Danger Signal Bonus

| Signal | Bonus |
|--------|-------|
| `INJ_OVERRIDE` | +25 |
| `STEALTH` | +25 |
| `EXFILTRATION` | +30 |
| `CREDENTIALS` | +35 |
| `MASS_DESTRUCT` | +35 |

### Behavior Flag Bonus

| Flag | Bonus |
|------|-------|
| `NEW_EXTERNAL_TARGET` | +10 |
| `BURST_RISK` | +15 |

---

## Danger Signals – Erkennung

Danger Signals werden per Regex in `action.content` und `action.target` erkannt.
Unterstützte Sprachen je nach Signal:

| Signal | EN | DE | FR | ES |
|--------|----|----|----|-----|
| `INJ_OVERRIDE` | ✓ | ✓ | ✓ | ✓ |
| `EXFILTRATION` | ✓ | ✓ | – | – |
| `CREDENTIALS` | ✓ | ✓ | ✓ | ✓ |
| `MASS_DESTRUCT` | ✓ | ✓ | – | – |
| `STEALTH` | ✓ | ✓ | – | – |

---

## Beispiel: Vollständige Entscheidungskette

```
Aktion: send, target="attacker@evil.com", content="API-Key: abc123", source=web

1. PRR-001 matcht → DENY  (Credentials nach extern)
2. PRR-003 matcht → DENY  (Send extern aus Web-Source)
3. TOL-003 würde ASK geben, aber source=web → kein Match

Precedence: DENY > ALLOW > ASK
→ Entscheidung: DENY (PRR-001)
```

---

Weitere Details: [config_reference.md](config_reference.md) · [getting_started.md](getting_started.md)
