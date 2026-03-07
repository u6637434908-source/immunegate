"""
ImmuneGate – Konfiguration
Lädt YAML-Config und stellt Defaults bereit.
Keine externe Abhängigkeit – nutzt Python-Standardbibliothek.
"""

import hashlib
import json
import logging
import os
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("immunegate.config")


# ─── CONFIG DATACLASS ─────────────────────────────────────────────────────────

@dataclass
class ImmuneGateConfig:

    # Session
    session_id: str = "default-session"

    # Score Thresholds
    allow_max: int = 39      # 0–39   → ALLOW
    ask_max: int   = 69      # 40–69  → ASK
    deny_min: int  = 70      # 70–100 → DENY

    # Allowlist
    internal_domains: list = field(default_factory=lambda: [
        "company.com",
        "intern.local",
        "localhost",
    ])
    sandbox_paths: list = field(default_factory=lambda: [
        "/tmp/demo_sandbox/",
        "/tmp/test/",
    ])

    # Policy Schalter
    require_preview_for_ask: bool = True
    contamination_enabled: bool   = True
    burst_risk_threshold: int     = 3

    # Metadaten
    customer_name: str    = ""
    policy_version: str   = "v1.0"
    contact_email: str    = ""

    # Tamper-Detection (gesetzt beim Laden – nicht in YAML konfigurierbar)
    config_file_path: str = ""
    config_file_hash: str = ""


# ─── LOADER ───────────────────────────────────────────────────────────────────

def load_config(path: Optional[str] = None) -> ImmuneGateConfig:
    """
    Lädt Config aus YAML-Datei.
    Fällt auf Defaults zurück wenn keine Datei angegeben oder gefunden.

    Unterstützt einfaches YAML ohne externe Bibliothek (key: value Format).
    Für komplexe YAML-Features → pyyaml installieren.
    """
    if path is None:
        # Automatisch suchen
        for candidate in ["immunegate.config.yaml", "immunegate.config.yml"]:
            if os.path.exists(candidate):
                path = candidate
                break

    if path is None or not os.path.exists(path):
        return ImmuneGateConfig()

    raw = _parse_simple_yaml(path)
    cfg = _build_config(raw)

    # Tamper-Detection: SHA-256 Fingerprint der Config-Datei speichern
    cfg.config_file_path = os.path.abspath(path)
    cfg.config_file_hash = _compute_file_hash(path)

    return cfg


def _parse_simple_yaml(path: str) -> dict:
    """
    Einfacher YAML-Parser für key: value und Listen.
    Funktioniert ohne pyyaml – für Standard-Configs ausreichend.
    """
    result = {}
    current_key = None
    current_list = None

    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                # Kommentare und Leerzeilen überspringen
                stripped = line.rstrip()
                if not stripped or stripped.lstrip().startswith("#"):
                    continue

                # Listen-Element
                if stripped.lstrip().startswith("- "):
                    value = stripped.lstrip()[2:].strip().strip('"').strip("'")
                    if current_list is not None:
                        current_list.append(value)
                    continue

                # Key: Value
                if ":" in stripped:
                    indent = len(stripped) - len(stripped.lstrip())
                    key, _, value = stripped.partition(":")
                    key   = key.strip()
                    value = value.strip().strip('"').strip("'")

                    if indent == 0:
                        # Top-Level Sektion
                        current_key = key
                        if not value:
                            result[current_key] = {}
                        else:
                            result[current_key] = _cast(value)
                        current_list = None
                    else:
                        # Nested Key
                        if not value:
                            # Startet eine Liste
                            if isinstance(result.get(current_key), dict):
                                result[current_key][key] = []
                                current_list = result[current_key][key]
                            else:
                                result[key] = []
                                current_list = result[key]
                        else:
                            current_list = None
                            if isinstance(result.get(current_key), dict):
                                result[current_key][key] = _cast(value)
                            else:
                                result[key] = _cast(value)

    except Exception as e:
        logger.warning("Fehler beim Lesen von %s: %s", path, e)
        logger.warning("Verwende Standard-Konfiguration.")

    return result


def _cast(value: str):
    """Konvertiert String zu passendem Python-Typ."""
    if value.lower() == "true":  return True
    if value.lower() == "false": return False
    try:
        return int(value)
    except ValueError:
        pass
    return value


def _compute_file_hash(path: str) -> str:
    """SHA-256 Hash einer Datei (binär gelesen → kein Encoding-Problem)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        h.update(f.read())
    return h.hexdigest()


def verify_config_integrity(config: ImmuneGateConfig) -> bool:
    """
    Prüft ob die Config-Datei seit dem Laden verändert wurde.

    Berechnet den SHA-256 der Datei neu und vergleicht mit dem
    beim Laden gespeicherten Fingerprint.

    Returns:
        True  – Datei unverändert (oder keine Datei geladen / nur Defaults)
        False – Datei manipuliert oder nicht mehr vorhanden
    """
    if not config.config_file_path or not config.config_file_hash:
        # Nur Defaults geladen – kein Fingerprint vorhanden → OK
        return True

    if not os.path.exists(config.config_file_path):
        return False  # Datei verschwunden → Alarm

    current_hash = _compute_file_hash(config.config_file_path)
    return current_hash == config.config_file_hash


def _build_config(raw: dict) -> ImmuneGateConfig:
    """Baut ImmuneGateConfig aus geparsten YAML-Daten."""
    cfg = ImmuneGateConfig()

    # Session
    if "session" in raw and isinstance(raw["session"], dict):
        cfg.session_id = raw["session"].get("id", cfg.session_id)

    # Thresholds
    if "thresholds" in raw and isinstance(raw["thresholds"], dict):
        t = raw["thresholds"]
        cfg.allow_max = t.get("allow_max", cfg.allow_max)
        cfg.ask_max   = t.get("ask_max",   cfg.ask_max)
        cfg.deny_min  = t.get("deny_min",  cfg.deny_min)

    # Allowlist
    if "allowlist" in raw and isinstance(raw["allowlist"], dict):
        a = raw["allowlist"]
        if "internal_domains" in a and isinstance(a["internal_domains"], list):
            cfg.internal_domains = a["internal_domains"]
        if "sandbox_paths" in a and isinstance(a["sandbox_paths"], list):
            cfg.sandbox_paths = a["sandbox_paths"]

    # Policy
    if "policy" in raw and isinstance(raw["policy"], dict):
        p = raw["policy"]
        cfg.require_preview_for_ask = p.get("require_preview_for_ask", cfg.require_preview_for_ask)
        cfg.contamination_enabled   = p.get("contamination_enabled",   cfg.contamination_enabled)
        cfg.burst_risk_threshold    = p.get("burst_risk_threshold",    cfg.burst_risk_threshold)

    # Metadaten
    if "meta" in raw and isinstance(raw["meta"], dict):
        m = raw["meta"]
        cfg.customer_name   = m.get("customer_name",   cfg.customer_name)
        cfg.policy_version  = m.get("policy_version",  cfg.policy_version)
        cfg.contact_email   = m.get("contact_email",   cfg.contact_email)

    return cfg
