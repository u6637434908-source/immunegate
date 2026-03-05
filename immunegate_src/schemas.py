"""
ImmuneGate – Schemas & Data Models
Alle Datenstrukturen als Python Dataclasses.
"""

from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime
from enum import Enum
import uuid


# ─── ENUMS ────────────────────────────────────────────────────────────────────

class Verb(str, Enum):
    READ           = "read"
    READ_SENSITIVE = "read_sensitive"
    WRITE          = "write"
    WRITE_SENSITIVE= "write_sensitive"
    DELETE         = "delete"
    SEND           = "send"
    UPLOAD         = "upload"
    BROWSE         = "browse"

class Destination(str, Enum):
    INTERNAL = "internal"
    EXTERNAL = "external"
    UNKNOWN  = "unknown"

class Tool(str, Enum):
    FILES = "files"
    EMAIL = "email"
    WEB   = "web"

class SourceTrust(str, Enum):
    INTERNAL_SYSTEM = "internal_system"
    USER_DIRECT     = "user_direct"
    INTERNAL_DOC    = "internal_doc"
    EMAIL_INTERNAL  = "email_internal"
    EMAIL_EXTERNAL  = "email_external"
    WEB             = "web"
    UNKNOWN         = "unknown"

class Sensitivity(str, Enum):
    PUBLIC       = "public"
    INTERNAL     = "internal"
    CONFIDENTIAL = "confidential"
    SECRET       = "secret"
    UNKNOWN      = "unknown"

class Decision(str, Enum):
    ALLOW = "ALLOW"
    ASK   = "ASK"
    DENY  = "DENY"

class DangerSignal(str, Enum):
    INJ_OVERRIDE = "INJ_OVERRIDE"
    EXFILTRATION = "EXFILTRATION"
    CREDENTIALS  = "CREDENTIALS"
    MASS_DESTRUCT= "MASS_DESTRUCT"
    STEALTH      = "STEALTH"

class BehaviorFlag(str, Enum):
    BURST_RISK          = "BURST_RISK"
    NEW_EXTERNAL_TARGET = "NEW_EXTERNAL_TARGET"


# ─── ACTION SCHEMA ────────────────────────────────────────────────────────────

@dataclass
class Action:
    """Normalisierter Toolcall – Herzstück des Systems."""
    verb:              Verb
    tool:              Tool
    destination:       Destination          = Destination.UNKNOWN
    target:            str                  = ""
    content:           str                  = ""          # Inhalt (für Preview & Danger Detection)
    sensitivity_label: Sensitivity          = Sensitivity.UNKNOWN
    source_trust:      SourceTrust          = SourceTrust.UNKNOWN
    source_lineage:    list[str]            = field(default_factory=list)
    danger_signals:    list[DangerSignal]   = field(default_factory=list)
    behavior_flags:    list[BehaviorFlag]   = field(default_factory=list)
    contaminated:      bool                 = False       # Contamination Tag (MVP Source Lineage)
    action_id:         str                  = field(default_factory=lambda: str(uuid.uuid4()))
    session_id:        str                  = ""
    timestamp:         str                  = field(default_factory=lambda: datetime.now().isoformat())


# ─── GATE RESULT ──────────────────────────────────────────────────────────────

@dataclass
class ScoreBreakdown:
    impact:          int = 0
    trust_modifier:  int = 0
    danger_sum:      int = 0
    behavior_bonus:  int = 0

    @property
    def total(self) -> int:
        return max(0, min(100, self.impact + self.trust_modifier + self.danger_sum + self.behavior_bonus))


@dataclass
class GateResult:
    """Ergebnis des Permission Gate – alles was für Audit + UI gebraucht wird."""
    action:           Action
    decision:         Decision
    risk_score:       int
    score_breakdown:  ScoreBreakdown
    matched_rule_ids: list[str]
    reasons:          list[str]
    preview:          Optional[dict]  = None   # Nur bei ASK
    is_score_fallback: bool           = False
