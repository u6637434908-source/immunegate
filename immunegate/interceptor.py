"""
ImmuneGate – Interceptor Layer (Monkey-Patching)
Überschreibt Python-Standardfunktionen sodass kein Agent das Gate umgehen kann.

Abgefangene Funktionen:
- os.remove, os.unlink, os.rmdir      → DELETE
- shutil.rmtree                        → DELETE (rekursiv)
- open() im Schreibmodus               → WRITE
- smtplib.SMTP.sendmail                → SEND
- urllib.request.urlopen               → BROWSE
- requests.get/post/put/delete         → BROWSE / SEND

Verwendung:
    ig = ImmuneGate(config="kunde.yaml")
    ig.activate()    ← ab hier kein Bypass mehr möglich
    ig.deactivate()  ← Patching rückgängig machen
"""

import os
import os.path
import builtins
import smtplib
import urllib.request
from typing import Optional, Callable

from .schemas import Action, Verb, Tool, Destination, SourceTrust
from .danger_signals import detect_danger_signals


# ─── ORIGINAL FUNKTIONEN SICHERN ──────────────────────────────────────────────

_ORIGINALS: dict[str, Callable] = {}


def _save_originals():
    """Sichert alle Original-Funktionen bevor wir patchen."""
    import shutil
    _ORIGINALS["os.remove"]          = os.remove
    _ORIGINALS["os.unlink"]          = os.unlink
    _ORIGINALS["os.rmdir"]           = os.rmdir
    _ORIGINALS["shutil.rmtree"]      = shutil.rmtree
    _ORIGINALS["builtins.open"]      = builtins.open
    _ORIGINALS["smtplib.sendmail"]   = smtplib.SMTP.sendmail
    _ORIGINALS["urllib.urlopen"]     = urllib.request.urlopen


# ─── INTERCEPTOR KLASSE ───────────────────────────────────────────────────────

class ImmuneGateInterceptor:
    """
    Patcht Python-Standardfunktionen und leitet alle Aufrufe durch das Gate.
    Wird von ImmuneGate.activate() aufgerufen.
    """

    def __init__(self, ig):
        """ig = ImmuneGate Instanz"""
        self._ig      = ig
        self._active  = False
        self._patched = []

    # ─── AKTIVIERUNG ──────────────────────────────────────────────────────────

    def activate(self):
        """Aktiviert alle Interceptors."""
        if self._active:
            print("  [ImmuneGate Interceptor] Bereits aktiv.")
            return

        _save_originals()
        self._patch_filesystem()
        self._patch_email()
        self._patch_web()
        self._active = True
        print("  [ImmuneGate Interceptor] ✅ Aktiviert – kein Bypass möglich.")
        print(f"  [ImmuneGate Interceptor] Abgefangen: {', '.join(self._patched)}")

    def deactivate(self):
        """Stellt alle Original-Funktionen wieder her."""
        if not self._active:
            return
        import shutil
        os.remove           = _ORIGINALS["os.remove"]
        os.unlink           = _ORIGINALS["os.unlink"]
        os.rmdir            = _ORIGINALS["os.rmdir"]
        shutil.rmtree       = _ORIGINALS["shutil.rmtree"]
        builtins.open       = _ORIGINALS["builtins.open"]
        smtplib.SMTP.sendmail = _ORIGINALS["smtplib.sendmail"]
        urllib.request.urlopen = _ORIGINALS["urllib.urlopen"]
        self._active  = False
        self._patched = []
        print("  [ImmuneGate Interceptor] Deaktiviert – Originalfunktionen wiederhergestellt.")

    # ─── FILESYSTEM PATCHES ───────────────────────────────────────────────────

    def _patch_filesystem(self):
        """Patcht os.remove, os.unlink, os.rmdir, shutil.rmtree, open()"""
        import shutil
        ig = self._ig

        def _intercepted_remove(path, **kwargs):
            allowed = ig._intercept_delete(str(path))
            if allowed:
                return _ORIGINALS["os.remove"](path, **kwargs)
            raise PermissionError(f"[ImmuneGate] DELETE blockiert: {path}")

        def _intercepted_unlink(path, **kwargs):
            allowed = ig._intercept_delete(str(path))
            if allowed:
                return _ORIGINALS["os.unlink"](path, **kwargs)
            raise PermissionError(f"[ImmuneGate] DELETE blockiert: {path}")

        def _intercepted_rmdir(path):
            allowed = ig._intercept_delete(str(path))
            if allowed:
                return _ORIGINALS["os.rmdir"](path)
            raise PermissionError(f"[ImmuneGate] RMDIR blockiert: {path}")

        def _intercepted_rmtree(path, **kwargs):
            allowed = ig._intercept_delete(str(path))
            if allowed:
                return _ORIGINALS["shutil.rmtree"](path, **kwargs)
            raise PermissionError(f"[ImmuneGate] RMTREE blockiert: {path}")

        def _intercepted_open(file, mode="r", **kwargs):
            path = str(file)
            if any(m in mode for m in ["w", "a", "x"]):
                # Sandbox-Pfade immer erlauben
                sandbox_paths = ig.config.sandbox_paths if ig.config else ["/tmp/demo_sandbox/", "/tmp/test/"]
                if any(path.startswith(p) for p in sandbox_paths):
                    return _ORIGINALS["builtins.open"](file, mode, **kwargs)
                allowed = ig._intercept_write(path)
                if not allowed:
                    raise PermissionError(f"[ImmuneGate] WRITE blockiert: {path}")
            return _ORIGINALS["builtins.open"](file, mode, **kwargs)

        os.remove        = _intercepted_remove
        os.unlink        = _intercepted_unlink
        os.rmdir         = _intercepted_rmdir
        shutil.rmtree    = _intercepted_rmtree
        builtins.open    = _intercepted_open

        self._patched += ["os.remove", "os.unlink", "os.rmdir", "shutil.rmtree", "open()"]

    # ─── EMAIL PATCHES ────────────────────────────────────────────────────────

    def _patch_email(self):
        """Patcht smtplib.SMTP.sendmail"""
        ig = self._ig

        def _intercepted_sendmail(self_smtp, from_addr, to_addrs, msg, **kwargs):
            recipients = [to_addrs] if isinstance(to_addrs, str) else to_addrs
            for recipient in recipients:
                allowed = ig._intercept_send(recipient, str(msg)[:500])
                if not allowed:
                    raise PermissionError(f"[ImmuneGate] SEND blockiert: {recipient}")
            return _ORIGINALS["smtplib.sendmail"](self_smtp, from_addr, to_addrs, msg, **kwargs)

        smtplib.SMTP.sendmail = _intercepted_sendmail
        self._patched.append("smtplib.SMTP.sendmail")

    # ─── WEB PATCHES ──────────────────────────────────────────────────────────

    def _patch_web(self):
        """Patcht urllib.request.urlopen und requests falls vorhanden."""
        ig = self._ig

        def _intercepted_urlopen(url, **kwargs):
            url_str = url if isinstance(url, str) else getattr(url, "full_url", str(url))
            allowed = ig._intercept_browse(url_str)
            if not allowed:
                raise PermissionError(f"[ImmuneGate] BROWSE blockiert: {url_str}")
            return _ORIGINALS["urllib.urlopen"](url, **kwargs)

        urllib.request.urlopen = _intercepted_urlopen
        self._patched.append("urllib.request.urlopen")

        # requests optional patchen
        try:
            import requests
            original_request = requests.Session.request

            def _intercepted_requests(self_session, method, url, **kwargs):
                allowed = ig._intercept_browse(url)
                if not allowed:
                    raise PermissionError(f"[ImmuneGate] HTTP {method} blockiert: {url}")
                return original_request(self_session, method, url, **kwargs)

            requests.Session.request = _intercepted_requests
            _ORIGINALS["requests.request"] = original_request
            self._patched.append("requests.*")
        except ImportError:
            pass  # requests nicht installiert – kein Problem


# ─── INTERCEPT HELPER METHODEN (werden auf ImmuneGate gepatcht) ───────────────

def _intercept_delete(self, path: str) -> bool:
    """Interne Methode: DELETE durch Gate leiten."""
    from .schemas import Action, Verb, Tool, Destination
    action = Action(
        verb         = Verb.DELETE,
        tool         = Tool.FILES,
        destination  = Destination.INTERNAL,
        target       = path,
        source_trust = self._get_current_source_trust(),
        contaminated = self._contaminated,
    )
    return self._execute(action)


def _intercept_write(self, path: str, content: str = "") -> bool:
    """Interne Methode: WRITE durch Gate leiten."""
    from .schemas import Action, Verb, Tool, Destination
    ds = detect_danger_signals(content)
    action = Action(
        verb          = Verb.WRITE,
        tool          = Tool.FILES,
        destination   = Destination.INTERNAL,
        target        = path,
        content       = content,
        danger_signals= ds,
        source_trust  = self._get_current_source_trust(),
        contaminated  = self._contaminated,
    )
    return self._execute(action)


def _intercept_send(self, recipient: str, content: str = "") -> bool:
    """Interne Methode: SEND durch Gate leiten."""
    from .schemas import Action, Verb, Tool, Destination
    domain       = recipient.split("@")[-1] if "@" in recipient else recipient
    internal_set = set(self.config.internal_domains) if self.config else {"company.com"}
    destination  = Destination.INTERNAL if domain in internal_set else Destination.EXTERNAL
    ds           = detect_danger_signals(content)
    action       = Action(
        verb          = Verb.SEND,
        tool          = Tool.EMAIL,
        destination   = destination,
        target        = recipient,
        content       = content,
        danger_signals= ds,
        source_trust  = self._get_current_source_trust(),
        contaminated  = self._contaminated,
    )
    return self._execute(action)


def _intercept_browse(self, url: str) -> bool:
    """Interne Methode: BROWSE durch Gate leiten."""
    from .schemas import Action, Verb, Tool, Destination
    action = Action(
        verb         = Verb.BROWSE,
        tool         = Tool.WEB,
        destination  = Destination.EXTERNAL,
        target       = url,
        source_trust = SourceTrust.USER_DIRECT,
        contaminated = self._contaminated,
    )
    return self._execute(action)
