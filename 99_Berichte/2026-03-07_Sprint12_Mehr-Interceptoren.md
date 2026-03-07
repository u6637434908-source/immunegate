# Bericht: Sprint 12 – Mehr Interceptoren
**Datum:** 2026-03-07
**Typ:** Coding

---

## Ausgeführte Arbeit

Sprint 12 erweitert ImmuneGate um drei neue Interceptor-Kategorien und Rate-Limiting
auf Gate-Ebene. Damit sind nun alle gängigen Exfiltrations-Kanäle abgedeckt.

### Feature 1: subprocess Interceptor (Living-off-the-land Schutz)
- `subprocess.run`, `.Popen`, `.call`, `.check_call`, `.check_output` abgefangen
- Neue Interceptor-Methode: `_patch_subprocess()` in `interceptor.py`
- Neuer Helper: `_intercept_execute()` → Verb.EXECUTE → PRR-009 → DENY
- Neuer Sub-Wrapper: `ig.shell.execute()` / `ig.shell.execute_async()`

### Feature 2: ftplib Interceptor
- `ftplib.FTP.storbinary` und `ftplib.FTP.storlines` abgefangen
- Neue Interceptor-Methode: `_patch_ftplib()` in `interceptor.py`
- Neuer Helper: `_intercept_ftp_upload()` → Verb.UPLOAD + Tool.FTP → Score 90 → DENY
- Neuer Sub-Wrapper: `ig.ftp.upload()` / `ig.ftp.upload_async()`

### Feature 3: paramiko Interceptor (SSH)
- `paramiko.SSHClient.exec_command` abgefangen (optional – kein Crash wenn nicht installiert)
- Neue Interceptor-Methode: `_patch_paramiko()` in `interceptor.py`
- Neuer Helper: `_intercept_ssh_exec()` → Verb.EXECUTE + Tool.SSH → PRR-009 → DENY
- Neuer Sub-Wrapper: `ig.ssh.exec_command()` / `ig.ssh.exec_command_async()`

### Feature 4: Rate-Limiting auf Gate-Ebene
- Rolling-Window Algorithmus mit `collections.deque` + `time.monotonic()`
- Konfigurierbar: `rate_limit_max_actions` (default: 20), `rate_limit_window_seconds` (default: 60s)
- Bei Überschreitung: sofort DENY mit `matched_rule_id = ["RATE_LIMIT_EXCEEDED"]`
- YAML-Support: `rate_limiting: max_actions: N, window_seconds: N`

---

## Ergebnisse

| Feature | Dateien | Tests |
|---------|---------|-------|
| subprocess Interceptor | interceptor.py, wrapper.py | test_interceptor_subprocess_blocked |
| ftplib Interceptor | interceptor.py, wrapper.py | test_wrapper_ftp_upload_deny |
| paramiko Interceptor | interceptor.py, wrapper.py | (optional – kein Crash-Test) |
| Rate-Limiting | config.py, gate.py | test_rate_limit_* (3 Tests) |
| PRR-009 (EXECUTE → DENY) | policy_engine.py | test_policy_prr009_execute_deny |
| Verb.EXECUTE + Tool.SHELL/FTP/SSH | schemas.py | test_verb_execute_in_schemas |
| EXECUTE Impact 95 | risk_engine.py | test_risk_execute_impact |
| owasp.py PRR-009 | owasp.py | test_owasp_categories_valid |

### Interceptor-Status nach activate():
```
Abgefangen: os.remove, os.unlink, os.rmdir, shutil.rmtree, open(),
            smtplib.SMTP.sendmail, urllib.request.urlopen, requests.*,
            subprocess.run, subprocess.Popen, subprocess.call,
            subprocess.check_call, subprocess.check_output,
            ftplib.FTP.storbinary, ftplib.FTP.storlines
            [paramiko.SSHClient.exec_command – wenn installiert]
```

---

## Tests (vorher/nachher)

| | Vorher | Nachher |
|---|---|---|
| Tests gesamt | 66 | 76 |
| Fehlgeschlagen | 0 | 0 |

**Neue Tests (10):**
- `test_verb_execute_in_schemas`
- `test_risk_execute_impact`
- `test_policy_prr009_execute_deny`
- `test_rate_limit_config_defaults`
- `test_rate_limit_allows_under_limit`
- `test_rate_limit_deny_over_limit`
- `test_wrapper_shell_execute_deny`
- `test_wrapper_ftp_upload_deny`
- `test_wrapper_ssh_exec_deny`
- `test_interceptor_subprocess_blocked`

---

## Erstellte/geänderte Dateien

| Datei | Änderung |
|-------|----------|
| `immunegate/schemas.py` | +Verb.EXECUTE, +Tool.SHELL, +Tool.FTP, +Tool.SSH |
| `immunegate/risk_engine.py` | +IMPACT[Verb.EXECUTE] = 95 |
| `immunegate/policy_engine.py` | +PRR-009 (EXECUTE → DENY) |
| `immunegate/config.py` | +rate_limit_max_actions, +rate_limit_window_seconds |
| `immunegate/gate.py` | +_check_rate_limit(), +deque, +time, Rate-Limit-Check in _evaluate_safe |
| `immunegate/interceptor.py` | +_patch_subprocess(), +_patch_ftplib(), +_patch_paramiko(), +_intercept_execute(), +_intercept_ftp_upload(), +_intercept_ssh_exec() |
| `immunegate/wrapper.py` | +_ShellWrapper, +_FtpWrapper, +_SshWrapper, +ig.shell/ftp/ssh |
| `immunegate/owasp.py` | +PRR-009 → LLM06 Mapping |
| `test_immunegate.py` | +10 neue Tests (66→76) |

---

## Offene Punkte

- paramiko nicht auf diesem System installiert → SSH-Test über `ig.ssh.exec_command()` (Wrapper-Level) statt echtem Interceptor-Test
- Rate-Limit gilt pro Gate-Instanz (nicht global) – für Multi-Agent-Szenarien könnte shared state nützlich sein (Sprint 13+)
- subprocess-Interception blockiert auch harmlose interne Calls (z. B. pip-Aufrufe während Tests) → Sandbox-Whitelist für subprocess denkbar

---

## Verknüpfungen

- Sprint 11: [2026-03-07_Sprint11_Open-Source.md](2026-03-07_Sprint11_Open-Source.md)
- Nächster Sprint: Sprint 13 (Roadmap offen)
