"""
ImmuneGate – Plugin System

Ermöglicht Kunden, eigene Policy-Regeln hinzuzufügen ohne den Core anzufassen.

Verwendung (Kunden-Code):
    from immunegate.plugins import BasePlugin
    from immunegate.policy_engine import PolicyMatch
    from immunegate.schemas import Action, Verb, Decision

    class MyPlugin(BasePlugin):
        def evaluate(self, action: Action) -> Optional[PolicyMatch]:
            if action.verb == Verb.DELETE:
                return PolicyMatch("MY-001", Decision.ASK, "Mein Grund")
            return None

Laden:
    ig = ImmuneGate(plugins="plugins/")

Sicherheitsgarantien:
    - Core-DENY kann von Plugins nicht überschrieben werden (DENY > ALLOW)
    - Fehler in Plugins → Plugin wird ignoriert, Gate läuft weiter (Fail-Safe)
    - Plugins sehen dieselbe Action wie die Core-Regeln (read-only)
"""

from __future__ import annotations

import importlib.util
import os
from abc import ABC, abstractmethod
from typing import Optional, List

from .schemas import Action
from .policy_engine import PolicyMatch


# ─── BASE CLASS ────────────────────────────────────────────────────────────────

class BasePlugin(ABC):
    """
    Basisklasse für alle ImmuneGate Plugins.

    Jedes Plugin erbt von BasePlugin und implementiert evaluate().
    Plugins werden nach den Core-Regeln ausgeführt und können Entscheidungen
    ergänzen oder einschränken.

    Precedence gilt global: DENY > ALLOW > ASK (egal ob Core oder Plugin).
    Core-DENY ist damit strukturell unüberwindbar.

    Fail-Safe: Exceptions in evaluate() werden intern abgefangen.
    Das Gate läuft immer weiter, auch bei Plugin-Fehlern.
    """

    @property
    def plugin_id(self) -> str:
        """Eindeutiger Bezeichner. Standard: Klassenname."""
        return self.__class__.__name__

    @abstractmethod
    def evaluate(self, action: Action) -> Optional[PolicyMatch]:
        """
        Bewertet eine Action.

        Returns:
            PolicyMatch mit decision ALLOW / ASK / DENY  →  Einfluss auf Entscheidung
            None                                         →  Plugin enthält sich

        Darf KEINE Exception werfen (wird intern abgefangen und ignoriert).
        """
        ...


# ─── LOADER ───────────────────────────────────────────────────────────────────

def load_plugins(plugins_dir: str) -> List[BasePlugin]:
    """
    Lädt alle Plugins aus einem Verzeichnis.

    Regeln:
    - Durchsucht *.py Dateien, ignoriert __init__.py und _prefix-Dateien
    - Jede Klasse die BasePlugin erweitert wird instanziiert
    - Fehler beim Import oder Instanziieren → Datei überspringen (Fail-Safe)
    - Reihenfolge: alphabetisch nach Dateiname

    Args:
        plugins_dir: Pfad zum Plugin-Verzeichnis (relativ oder absolut)

    Returns:
        Liste von BasePlugin-Instanzen (leer wenn Verzeichnis fehlt oder leer)
    """
    plugins: List[BasePlugin] = []

    if not os.path.isdir(plugins_dir):
        return plugins

    for filename in sorted(os.listdir(plugins_dir)):
        if not filename.endswith(".py") or filename.startswith("_"):
            continue

        filepath    = os.path.join(plugins_dir, filename)
        module_name = filename[:-3]

        try:
            spec   = importlib.util.spec_from_file_location(module_name, filepath)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            for attr_name in dir(module):
                obj = getattr(module, attr_name)
                if (isinstance(obj, type)
                        and issubclass(obj, BasePlugin)
                        and obj is not BasePlugin):
                    plugins.append(obj())

        except Exception:
            pass    # Fail-Safe: defekte Plugin-Datei → überspringen

    return plugins


# ─── RUNNER ───────────────────────────────────────────────────────────────────

def run_plugins(plugins: List[BasePlugin], action: Action) -> List[PolicyMatch]:
    """
    Führt alle Plugins gegen eine Action aus.

    Einzelne Plugin-Fehler werden ignoriert (Fail-Safe).
    Das Gate läuft weiter, auch wenn alle Plugins crashen.

    Returns:
        Liste der PolicyMatch-Objekte aller Plugins (None-Rückgaben ausgeschlossen)
    """
    matches: List[PolicyMatch] = []

    for plugin in plugins:
        try:
            result = plugin.evaluate(action)
            if result is not None:
                matches.append(result)
        except Exception:
            pass    # Fail-Safe: Plugin-Fehler → ignorieren

    return matches
