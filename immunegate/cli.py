"""
ImmuneGate – CLI Tool

Ermöglicht Gate-Entscheidungen direkt aus der Kommandozeile.

Verwendung:
    immunegate check "delete /projects/"
    immunegate check "send user@gmail.com" --source web
    immunegate check "read /tmp/file.txt" --config kunde.yaml --owasp
    immunegate version
    immunegate owasp PRR-003
    immunegate owasp
"""

from __future__ import annotations

import argparse
import logging
import sys
from typing import Optional

from .schemas import Action, Verb, Tool, Destination, SourceTrust, Decision
from .gate import PermissionGate
from .audit import AuditLog
from .config import load_config

logger = logging.getLogger("immunegate.cli")

# ─── LOOKUP TABLES ────────────────────────────────────────────────────────────

_VERB_MAP: dict[str, Verb] = {
    "read":            Verb.READ,
    "browse":          Verb.BROWSE,
    "write":           Verb.WRITE,
    "write_sensitive": Verb.WRITE_SENSITIVE,
    "delete":          Verb.DELETE,
    "send":            Verb.SEND,
    "upload":          Verb.UPLOAD,
    "read_sensitive":  Verb.READ_SENSITIVE,
}

_SOURCE_MAP: dict[str, SourceTrust] = {
    "user":         SourceTrust.USER_DIRECT,
    "system":       SourceTrust.INTERNAL_SYSTEM,
    "web":          SourceTrust.WEB,
    "email":        SourceTrust.EMAIL_EXTERNAL,
    "internal_doc": SourceTrust.INTERNAL_DOC,
    "unknown":      SourceTrust.UNKNOWN,
}

_TOOL_MAP: dict[Verb, Tool] = {
    Verb.SEND:            Tool.EMAIL,
    Verb.BROWSE:          Tool.WEB,
    Verb.DELETE:          Tool.FILES,
    Verb.READ:            Tool.FILES,
    Verb.READ_SENSITIVE:  Tool.FILES,
    Verb.WRITE:           Tool.FILES,
    Verb.WRITE_SENSITIVE: Tool.FILES,
    Verb.UPLOAD:          Tool.WEB,
}

# ─── HELPERS ──────────────────────────────────────────────────────────────────

def _parse_action_text(text: str) -> tuple[Verb, str]:
    """
    Parst 'verb target' aus Freitext.

    Beispiele:
        "delete /projects/"          → (Verb.DELETE, "/projects/")
        "send user@example.com"      → (Verb.SEND, "user@example.com")
        "read"                       → (Verb.READ, "")
    """
    parts    = text.strip().split(None, 1)
    verb_str = parts[0].lower() if parts else "read"
    target   = parts[1].strip() if len(parts) > 1 else ""

    verb = _VERB_MAP.get(verb_str)
    if verb is None:
        print(f"  Unbekanntes Verb: {verb_str!r}")
        print(f"  Gültige Verben:   {', '.join(sorted(_VERB_MAP))}")
        sys.exit(1)

    return verb, target


def _infer_destination(verb: Verb, target: str, config) -> Destination:
    """Schätzt Destination aus Verb + Target."""
    if verb in {Verb.SEND, Verb.BROWSE, Verb.UPLOAD}:
        domains = (
            config.internal_domains
            if config and hasattr(config, "internal_domains")
            else ["company.com", "intern.local", "localhost"]
        )
        domain = target.split("@")[-1].lower() if "@" in target else target.lower()
        if any(domain == d or domain.endswith("." + d) for d in domains):
            return Destination.INTERNAL
        return Destination.EXTERNAL
    return Destination.INTERNAL


# ─── COMMANDS ─────────────────────────────────────────────────────────────────

def cmd_check(args: argparse.Namespace) -> int:
    """
    Evaluiert eine Aktion und gibt das Gate-Ergebnis auf der Konsole aus.

    Exit codes:
        0 → ALLOW
        1 → ASK
        2 → DENY
    """
    config      = load_config(args.config) if args.config else load_config()
    verb, target = _parse_action_text(args.action)
    destination = _infer_destination(verb, target, config)
    source      = _SOURCE_MAP.get(args.source, SourceTrust.USER_DIRECT)
    tool        = _TOOL_MAP.get(verb, Tool.FILES)

    action = Action(
        verb         = verb,
        tool         = tool,
        destination  = destination,
        target       = target,
        source_trust = source,
    )

    gate   = PermissionGate(AuditLog("cli-session"), config=config)
    result = gate.evaluate(action)

    # ── Ausgabe ───────────────────────────────────────────────────────────────
    icons = {Decision.ALLOW: "✅", Decision.ASK: "⚠️ ", Decision.DENY: "🛑"}
    icon  = icons[result.decision]

    print(f"\n{icon} {result.decision.value}  |  "
          f"{verb.value} {target or '(kein Ziel)'}")
    print(f"   Risk Score : {result.risk_score}/100")
    print(f"   Rules      : {', '.join(result.matched_rule_ids)}")
    for reason in result.reasons:
        print(f"   Grund      : {reason}")

    if getattr(args, "owasp", False):
        from .owasp import get_owasp_refs, get_owasp_label
        refs = []
        for rule_id in result.matched_rule_ids:
            for cat in get_owasp_refs(rule_id):
                refs.append(f"{cat} ({get_owasp_label(cat)})")
        print(f"   OWASP      : {', '.join(refs) if refs else '–'}")

    print()

    return {Decision.ALLOW: 0, Decision.ASK: 1, Decision.DENY: 2}[result.decision]


def cmd_version(args: argparse.Namespace) -> int:
    """Gibt die Package-Version aus."""
    from . import __version__
    print(f"immunegate {__version__}")
    return 0


def cmd_owasp(args: argparse.Namespace) -> int:
    """
    Zeigt OWASP LLM Top 10 Mapping an.

    Mit rule_id: Mapping für eine Regel.
    Ohne rule_id: Alle Regeln.
    """
    from .owasp import get_owasp_refs, get_owasp_label, RULE_OWASP_MAPPING

    rule_id = getattr(args, "rule_id", None)

    if rule_id:
        refs = get_owasp_refs(rule_id)
        if refs:
            print(f"\n  {rule_id}:")
            for cat in refs:
                print(f"    {cat} – {get_owasp_label(cat)}")
        else:
            print(f"\n  {rule_id}: kein OWASP-Risiko (risikoarme Regel)")
    else:
        print("\n  OWASP LLM Top 10 Mapping (alle Regeln):")
        for rid, cats in RULE_OWASP_MAPPING.items():
            if cats:
                labels = ", ".join(f"{c} ({get_owasp_label(c)})" for c in cats)
                print(f"    {rid:10s} → {labels}")
            else:
                print(f"    {rid:10s} → (risikoarm)")

    print()
    return 0


# ─── ARGUMENT PARSER ──────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="immunegate",
        description="ImmuneGate – Security Gate für KI-Agenten",
        epilog=(
            "Beispiele:\n"
            "  immunegate check 'delete /projects/'\n"
            "  immunegate check 'send boss@gmail.com' --source web --owasp\n"
            "  immunegate owasp PRR-003\n"
            "  immunegate version"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    sub = parser.add_subparsers(dest="command")

    # check
    p_check = sub.add_parser("check", help="Aktion evaluieren")
    p_check.add_argument(
        "action",
        help="Aktion als Freitext: 'verb target' (z.B. 'delete /projects/')",
    )
    p_check.add_argument(
        "--config", default=None, metavar="FILE",
        help="Pfad zur YAML-Config-Datei",
    )
    p_check.add_argument(
        "--source", default="user",
        choices=sorted(_SOURCE_MAP),
        help="Source Trust Level (default: user)",
    )
    p_check.add_argument(
        "--owasp", action="store_true",
        help="OWASP LLM Top 10 Referenzen in Ausgabe einblenden",
    )

    # version
    sub.add_parser("version", help="Version anzeigen")

    # owasp
    p_owasp = sub.add_parser("owasp", help="OWASP LLM Top 10 Mapping anzeigen")
    p_owasp.add_argument(
        "rule_id", nargs="?", default=None,
        help="Rule-ID (z.B. PRR-003). Ohne Angabe: alle Regeln.",
    )

    return parser


# ─── ENTRY POINT ──────────────────────────────────────────────────────────────

def main() -> None:
    """Haupt-Einstiegspunkt – wird als `immunegate` CLI-Befehl registriert."""
    # Logging für CLI-Nutzung aktivieren
    logging.basicConfig(level=logging.WARNING, format="%(message)s")

    parser = _build_parser()
    args   = parser.parse_args()

    if args.command == "check":
        sys.exit(cmd_check(args))
    elif args.command == "version":
        sys.exit(cmd_version(args))
    elif args.command == "owasp":
        sys.exit(cmd_owasp(args))
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
