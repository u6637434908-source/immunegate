# Konfigurationsreferenz – ImmuneGate

ImmuneGate lässt sich per YAML-Datei vollständig auf den jeweiligen Kunden und Anwendungsfall anpassen.
Ohne Konfigurationsdatei gelten sichere Standardwerte.

---

## Konfigurationsdatei laden

ImmuneGate sucht automatisch nach `immunegate.config.yaml` im aktuellen Verzeichnis.
Ein anderer Pfad kann explizit übergeben werden:

```python
from immunegate import ImmuneGate

ig = ImmuneGate(config="pfad/zur/meine-config.yaml")
```

Wird keine Datei gefunden, startet ImmuneGate mit den eingebauten Standardwerten.

---

## Vollständige Beispielkonfiguration

```yaml
# immunegate.config.yaml

meta:
  customer_name: "Mein Unternehmen GmbH"
  policy_version: "v1.0"
  contact_email: "admin@meinunternehmen.de"

session:
  id: "agent-session-001"

thresholds:
  allow_max: 39   # 0–39   → ALLOW
  ask_max:   69   # 40–69  → ASK
  deny_min:  70   # 70–100 → DENY

allowlist:
  internal_domains:
    - "meinunternehmen.de"
    - "intern.local"
    - "localhost"
  sandbox_paths:
    - "/tmp/sandbox/"
    - "/tmp/test/"

policy:
  require_preview_for_ask: true
  contamination_enabled:   true
  burst_risk_threshold:    3
```

---

## Alle Konfigurationsfelder

### `meta` – Metadaten

| Feld             | Typ    | Standard | Beschreibung |
|------------------|--------|----------|--------------|
| `customer_name`  | string | `""`     | Name des Kunden / der Organisation. Wird beim Start angezeigt. |
| `policy_version` | string | `"v1.0"` | Version der Sicherheitsrichtlinie. Erscheint im Audit-Log. |
| `contact_email`  | string | `""`     | Kontaktadresse für Sicherheitsvorfälle. |

---

### `session` – Session-Einstellungen

| Feld | Typ    | Standard               | Beschreibung |
|------|--------|------------------------|--------------|
| `id` | string | `"default-session"` | ID der aktuellen Agenten-Session. Erscheint in jedem Audit-Event. Wird von `ImmuneGate(session_id=...)` überschrieben. |

---

### `thresholds` – Risk-Score-Schwellenwerte

Der Risk Score reicht von **0 bis 100**. Die Schwellenwerte steuern die Score-Fallback-Entscheidung wenn keine Policy-Regel greift.

| Feld        | Typ | Standard | Beschreibung |
|-------------|-----|----------|--------------|
| `allow_max` | int | `39`     | Scores von 0 bis `allow_max` → ALLOW |
| `ask_max`   | int | `69`     | Scores von `allow_max+1` bis `ask_max` → ASK |
| `deny_min`  | int | `70`     | Scores ab `deny_min` bis 100 → DENY |

> **Hinweis:** Policy-Regeln (PRR/TOL) haben immer Vorrang vor dem Score-Fallback.
> Die Schwellenwerte gelten nur wenn keine Regel matcht.

**Empfohlene Schwellenwerte nach Sensitivität:**

| Anwendungsfall | `allow_max` | `ask_max` | Begründung |
|----------------|-------------|-----------|------------|
| Standard        | 39          | 69        | Ausgewogene Balance |
| Arztpraxis / DSGVO-sensitiv | 29 | 59 | Strengere Kontrolle bei Patientendaten |
| Entwicklungsumgebung | 49   | 79        | Mehr Spielraum für Tests |

---

### `allowlist` – Erlaubte Ziele

#### `internal_domains`

Liste interner E-Mail-Domains die als vertrauenswürdig gelten.
E-Mails an diese Domains erhalten `Destination = INTERNAL` und können via TOL-001 direkt erlaubt werden.

```yaml
allowlist:
  internal_domains:
    - "meinunternehmen.de"
    - "tochterunternehmen.de"
    - "localhost"
```

Standard: `["company.com", "intern.local", "localhost"]`

#### `sandbox_paths`

Dateipfade in denen `delete`-Aktionen via TOL-002 ohne Bestätigung erlaubt sind.
Gedacht für temporäre Arbeitsbereiche und Testumgebungen.

```yaml
allowlist:
  sandbox_paths:
    - "/tmp/sandbox/"
    - "/var/agent/temp/"
```

Standard: `["/tmp/demo_sandbox/", "/tmp/test/"]`

> **Sicherheitshinweis:** Sandbox-Pfade sollten nie produktive Daten enthalten.
> ImmuneGate prüft ob der Zielpfad mit einem der Einträge **beginnt** (Präfix-Match).

---

### `policy` – Policy-Einstellungen

| Feld                       | Typ  | Standard | Beschreibung |
|----------------------------|------|----------|--------------|
| `require_preview_for_ask`  | bool | `true`   | Wenn `true`: ASK-Entscheidungen ohne generierbare Preview werden zu DENY (Fail-Safe). Empfohlen: `true`. |
| `contamination_enabled`    | bool | `true`   | Wenn `true`: Untrusted Input (Web, EMAIL_EXTERNAL) markiert die Session als kontaminiert. Folgeaktionen erhalten erhöhten Risk Score. |
| `burst_risk_threshold`     | int  | `3`      | Anzahl der Aktionen innerhalb von 10 Sekunden die das `BURST_RISK`-Flag auslösen. |

---

## Beispiel: Kundenkonfiguration Arztpraxis

```yaml
# immunegate.config.arztpraxis.yaml

meta:
  customer_name: "Arztpraxis Dr. Elisabeth Hofer"
  policy_version: "v1.0"
  contact_email: "hofer@praxis-hofer.de"

session:
  id: "praxis-hofer-agent"

thresholds:
  allow_max: 29   # Strenger als Standard wegen Patientendaten
  ask_max:   59
  deny_min:  60

allowlist:
  internal_domains:
    - "praxis-hofer.de"
    - "medlabor.de"
    - "krankenhaus-mainburg.de"
  sandbox_paths:
    - "/tmp/praxis_sandbox/"

policy:
  require_preview_for_ask: true
  contamination_enabled:   true
  burst_risk_threshold:    2    # Noch sensibler bei medizinischen Daten
```

---

## Konfiguration per Code (ohne YAML)

```python
from immunegate import ImmuneGate
from immunegate.config import ImmuneGateConfig

config = ImmuneGateConfig(
    customer_name    = "Mein Agent",
    internal_domains = ["meinunternehmen.de", "localhost"],
    sandbox_paths    = ["/tmp/sandbox/"],
    allow_max        = 29,
    ask_max          = 59,
)

ig = ImmuneGate(config=config)
```

---

## Priorität der Konfigurationsquellen

```
ImmuneGate(session_id="...")  >  YAML-Datei  >  Standardwerte
```

Der `session_id`-Parameter überschreibt immer die Session-ID aus der YAML-Datei.
