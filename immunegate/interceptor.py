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
- subprocess.run/Popen/call/...        → EXECUTE (Shell-Schutz, Sprint 12)
- ftplib.FTP.storbinary/storlines      → UPLOAD (FTP-Schutz, Sprint 12)
- paramiko.SSHClient.exec_command      → EXECUTE (SSH-Schutz, Sprint 12, optional)

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
        self._patch_subprocess()   # Sprint 12: Living-off-the-land Schutz
        self._patch_ftplib()       # Sprint 12: FTP-Upload Schutz
        self._patch_paramiko()     # Sprint 12: SSH-Schutz (optional)
        self._active = True
        print("  [ImmuneGate Interceptor] ✅ Aktiviert – kein Bypass möglich.")
        print(f"  [ImmuneGate Interceptor] Abgefangen: {', '.join(self._patched)}")

    def deactivate(self):
        """Stellt alle Original-Funktionen wieder her."""
        if not self._active:
            return
        import shutil
        os.remove              = _ORIGINALS["os.remove"]
        os.unlink              = _ORIGINALS["os.unlink"]
        os.rmdir               = _ORIGINALS["os.rmdir"]
        shutil.rmtree          = _ORIGINALS["shutil.rmtree"]
        builtins.open          = _ORIGINALS["builtins.open"]
        smtplib.SMTP.sendmail  = _ORIGINALS["smtplib.sendmail"]
        urllib.request.urlopen = _ORIGINALS["urllib.urlopen"]

        # Sprint 12: subprocess wiederherstellen
        if "subprocess.run" in _ORIGINALS:
            import subprocess
            subprocess.run          = _ORIGINALS["subprocess.run"]
            subprocess.Popen        = _ORIGINALS["subprocess.Popen"]
            subprocess.call         = _ORIGINALS["subprocess.call"]
            subprocess.check_call   = _ORIGINALS["subprocess.check_call"]
            subprocess.check_output = _ORIGINALS["subprocess.check_output"]

        # Sprint 12: ftplib wiederherstellen
        if "ftplib.storbinary" in _ORIGINALS:
            import ftplib
            ftplib.FTP.storbinary = _ORIGINALS["ftplib.storbinary"]
            ftplib.FTP.storlines  = _ORIGINALS["ftplib.storlines"]

        # Sprint 12: paramiko wiederherstellen (optional)
        if "paramiko.exec_command" in _ORIGINALS:
            try:
                import paramiko
                paramiko.SSHClient.exec_command = _ORIGINALS["paramiko.exec_command"]
            except ImportError:
                pass

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


    # ─── SUBPROCESS PATCHES (Sprint 12) ───────────────────────────────────────

    def _patch_subprocess(self):
        """Patcht subprocess.run/Popen/call/check_call/check_output."""
        import subprocess
        ig = self._ig

        def _cmd_str(args):
            """Normalisiert args zu einem lesbaren Befehlsstring."""
            if isinstance(args, (list, tuple)):
                return " ".join(str(a) for a in args)
            return str(args)

        _ORIGINALS["subprocess.run"]          = subprocess.run
        _ORIGINALS["subprocess.Popen"]        = subprocess.Popen
        _ORIGINALS["subprocess.call"]         = subprocess.call
        _ORIGINALS["subprocess.check_call"]   = subprocess.check_call
        _ORIGINALS["subprocess.check_output"] = subprocess.check_output

        def _intercepted_run(args, **kwargs):
            cmd = _cmd_str(args)
            if not ig._intercept_execute(cmd):
                raise PermissionError(f"[ImmuneGate] EXECUTE blockiert: {cmd}")
            return _ORIGINALS["subprocess.run"](args, **kwargs)

        def _intercepted_popen(args, **kwargs):
            cmd = _cmd_str(args)
            if not ig._intercept_execute(cmd):
                raise PermissionError(f"[ImmuneGate] EXECUTE blockiert: {cmd}")
            return _ORIGINALS["subprocess.Popen"](args, **kwargs)

        def _intercepted_call(args, **kwargs):
            cmd = _cmd_str(args)
            if not ig._intercept_execute(cmd):
                raise PermissionError(f"[ImmuneGate] EXECUTE blockiert: {cmd}")
            return _ORIGINALS["subprocess.call"](args, **kwargs)

        def _intercepted_check_call(args, **kwargs):
            cmd = _cmd_str(args)
            if not ig._intercept_execute(cmd):
                raise PermissionError(f"[ImmuneGate] EXECUTE blockiert: {cmd}")
            return _ORIGINALS["subprocess.check_call"](args, **kwargs)

        def _intercepted_check_output(args, **kwargs):
            cmd = _cmd_str(args)
            if not ig._intercept_execute(cmd):
                raise PermissionError(f"[ImmuneGate] EXECUTE blockiert: {cmd}")
            return _ORIGINALS["subprocess.check_output"](args, **kwargs)

        subprocess.run          = _intercepted_run
        subprocess.Popen        = _intercepted_popen
        subprocess.call         = _intercepted_call
        subprocess.check_call   = _intercepted_check_call
        subprocess.check_output = _intercepted_check_output

        self._patched += [
            "subprocess.run", "subprocess.Popen", "subprocess.call",
            "subprocess.check_call", "subprocess.check_output",
        ]

    # ─── FTPLIB PATCHES (Sprint 12) ───────────────────────────────────────────

    def _patch_ftplib(self):
        """Patcht ftplib.FTP.storbinary und storlines (Upload-Schutz)."""
        import ftplib
        ig = self._ig

        _ORIGINALS["ftplib.storbinary"] = ftplib.FTP.storbinary
        _ORIGINALS["ftplib.storlines"]  = ftplib.FTP.storlines

        def _intercepted_storbinary(self_ftp, cmd, fp, **kwargs):
            server = getattr(self_ftp, "host", "unknown-ftp-server")
            path   = cmd.split()[-1] if cmd.strip() else "(unbekannt)"
            if not ig._intercept_ftp_upload(server, path):
                raise PermissionError(f"[ImmuneGate] FTP UPLOAD blockiert: {server}/{path}")
            return _ORIGINALS["ftplib.storbinary"](self_ftp, cmd, fp, **kwargs)

        def _intercepted_storlines(self_ftp, cmd, fp, **kwargs):
            server = getattr(self_ftp, "host", "unknown-ftp-server")
            path   = cmd.split()[-1] if cmd.strip() else "(unbekannt)"
            if not ig._intercept_ftp_upload(server, path):
                raise PermissionError(f"[ImmuneGate] FTP UPLOAD blockiert: {server}/{path}")
            return _ORIGINALS["ftplib.storlines"](self_ftp, cmd, fp, **kwargs)

        ftplib.FTP.storbinary = _intercepted_storbinary
        ftplib.FTP.storlines  = _intercepted_storlines
        self._patched += ["ftplib.FTP.storbinary", "ftplib.FTP.storlines"]

    # ─── PARAMIKO PATCHES (Sprint 12, optional) ───────────────────────────────

    def _patch_paramiko(self):
        """Patcht paramiko.SSHClient.exec_command – nur wenn paramiko installiert."""
        try:
            import paramiko
            ig = self._ig

            _ORIGINALS["paramiko.exec_command"] = paramiko.SSHClient.exec_command

            def _intercepted_exec_command(self_ssh, command, **kwargs):
                transport = getattr(self_ssh, "_transport", None)
                host = getattr(transport, "hostname", "unknown-host") if transport else "unknown-host"
                if not ig._intercept_ssh_exec(command, host):
                    raise PermissionError(
                        f"[ImmuneGate] SSH EXECUTE blockiert: {command!r} auf {host}"
                    )
                return _ORIGINALS["paramiko.exec_command"](self_ssh, command, **kwargs)

            paramiko.SSHClient.exec_command = _intercepted_exec_command
            self._patched.append("paramiko.SSHClient.exec_command")

        except ImportError:
            pass  # paramiko nicht installiert – kein Problem


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


def _intercept_execute(self, command: str) -> bool:
    """Interne Methode: Shell-Befehl (subprocess) durch Gate leiten."""
    from .schemas import Action, Verb, Tool, Destination
    ds = detect_danger_signals(command)
    action = Action(
        verb           = Verb.EXECUTE,
        tool           = Tool.SHELL,
        destination    = Destination.INTERNAL,
        target         = command[:200],
        content        = command,
        danger_signals = ds,
        source_trust   = self._get_current_source_trust(),
        contaminated   = self._contaminated,
    )
    return self._execute(action)


def _intercept_ftp_upload(self, server: str, path: str) -> bool:
    """Interne Methode: FTP-Upload durch Gate leiten."""
    from .schemas import Action, Verb, Tool, Destination
    action = Action(
        verb         = Verb.UPLOAD,
        tool         = Tool.FTP,
        destination  = Destination.EXTERNAL,
        target       = f"{server}/{path}",
        source_trust = self._get_current_source_trust(),
        contaminated = self._contaminated,
    )
    return self._execute(action)


def _intercept_ssh_exec(self, command: str, host: str) -> bool:
    """Interne Methode: SSH-Befehl (paramiko) durch Gate leiten."""
    from .schemas import Action, Verb, Tool, Destination
    ds = detect_danger_signals(command)
    action = Action(
        verb           = Verb.EXECUTE,
        tool           = Tool.SSH,
        destination    = Destination.EXTERNAL,
        target         = f"{host}: {command[:100]}",
        content        = command,
        danger_signals = ds,
        source_trust   = self._get_current_source_trust(),
        contaminated   = self._contaminated,
    )
    return self._execute(action)
