"""
service_units.py — the thing that starts a supervised run after a reboot.

``--supervise`` keeps an engagement alive across a CRASH, inside one process.
It does not survive the two interruptions a multi-day operation actually
meets: the operator closes the terminal, or the machine reboots. For those,
something outside the process has to start it again — and that something is an
OS service definition, which is what this module renders.

The split is deliberate and strict:

* **rendering** is a PURE function of (command, working_dir, name): no
  subprocess, no filesystem, no import side effect. ``--print-service`` is
  therefore reviewable before anything is installed, and a renderer that grows
  a side effect would break that promise;
* **installing** is the ONE function that writes a file
  (``install_service``), and it never runs ``systemctl``/``launchctl``/
  ``schtasks``. The activation command is returned as TEXT for the operator to
  run: a framework that silently enables a boot-level service while nobody is
  looking is a framework an operator cannot audit.

What the unit is given is the operator's own invocation, verbatim: the same
targets, the same posture flags, plus ``--supervise`` and ``--resume-latest``.
That last pair is why an OS-level restart is safe rather than a way to sidestep
the crash budget: the relaunched process asks ``utils/auto_resume`` for
permission, and the budget lives in a file next to the checkpoint — so a
service that restarts forever still stops with a reason after N attempts.

Argument injection is the real hazard here, not the unit syntax. An
``ExecStart`` that re-splits its own arguments turns a target into flags (or
into a second command) in the operator's boot configuration, where nobody is
watching the first time it happens; a plist whose ``ProgramArguments`` were
built by string-joining has the same problem. So every argument is quoted by
ONE helper per platform, and the tests parse the result back and compare the
argument LIST — never the string.
"""

from __future__ import annotations

import hashlib
import os
import platform
import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, Optional, Sequence, Tuple

__all__ = [
    "KINDS",
    "content_digest",
    "default_name",
    "file_digest",
    "host_kind",
    "install_service",
    "invocation_digest",
    "plan_service",
    "render_launchd_plist",
    "render_systemd_unit",
    "render_unit",
    "render_windows_task_xml",
    "service_path",
    "supported",
    "uninstall_service",
]


def invocation_digest(command: Sequence[str]) -> str:
    """sha256 of the exact argv the unit will run — the invocation's identity.

    The unit records WHAT the engagement agreed to (`--auto <targets> ...`),
    and this is the value an operator can compare between the moment of
    `--install-service` and the file/audit trail later: the arguments are
    joined with NUL so `["a b", "c"]` and `["a", "b c"]` cannot collide, and
    the order is part of the identity.
    """
    payload = "\x00".join(str(part) for part in command)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def content_digest(content: str, encoding: str = "utf-8") -> str:
    """sha256 of the BYTES a unit file will hold (encoding included)."""
    return hashlib.sha256(str(content).encode(encoding)).hexdigest()


def file_digest(path: str) -> str:
    """sha256 of a file's bytes, or "" when there is no file to read."""
    try:
        with open(path, "rb") as handle:
            return hashlib.sha256(handle.read()).hexdigest()
    except (OSError, TypeError):
        return ""

#: the three unit formats this module knows how to render
KINDS = ("systemd", "launchd", "schtasks")

#: OS as this module sees it. A module constant (not a bare platform call) so
#: a test can ask about another OS through `supported(..., host_os="...")`.
HOST_OS = platform.system().lower()

#: default service name per format. launchd requires a reverse-DNS label
#: (a bare `phantom-auto` label is accepted but reads as a mistake).
_DEFAULT_NAMES = {
    "systemd": "phantom-auto",
    "launchd": "com.phantom.auto",
    "schtasks": "PhantomAutoMode",
}

#: which OS each format belongs to
_OS_FOR_KIND = {"systemd": ("linux",), "launchd": ("darwin", "macos"),
                "schtasks": ("windows",)}

#: A service name ends up in a path. Refusing separators is what keeps
#: `--service-name ../../etc/cron.d/x` from writing outside the unit directory.
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

#: Flags whose VALUE is a credential. A unit is world-readable and sits in a
#: well-known place, so a command line carrying one of these is refused rather
#: than written: the operator can pass the value to the service environment
#: themselves, and this module cannot un-write a file it already wrote.
_SECRET_FLAGS = frozenset((
    "--token", "--api-token", "--key", "--api-key", "--apikey", "--secret",
    "--password", "--pass", "--psk", "--auth", "--bearer", "--credential",
))

#: A `KEY=secret` style argument that smells like a credential assignment.
_SECRET_ASSIGNMENT = re.compile(
    r"^(?:[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|APIKEY|API_KEY|PSK|"
    r"CREDENTIAL)[A-Z0-9_]*)=(?P<value>.+)$")


# ── guards ─────────────────────────────────────────────────────────────────

def _safe_name(name: str) -> str:
    """Validate a service name that will become a filename."""
    text = (name or "").strip()
    if not _SAFE_NAME.match(text):
        raise ValueError(
            f"invalid service name {name!r}: letters, digits, dot, dash and "
            f"underscore only (it becomes a filename)")
    return text


def _assert_no_secret(command: Sequence[str]) -> None:
    """Refuse a command line that carries a credential into a boot file."""
    for arg in [str(a) for a in command]:
        flag = arg.split("=", 1)[0].lower()
        if flag in _SECRET_FLAGS:
            raise ValueError(
                f"refusing to write a service unit: {flag} carries a secret "
                f"value (a unit is world-readable and lives in a well-known "
                f"path)")
        if _SECRET_ASSIGNMENT.match(arg):
            raise ValueError(
                f"refusing to write a service unit: {arg.split('=', 1)[0]} "
                f"carries a secret value")


# ── per-platform quoting (ONE helper per platform, used by every renderer) ─

def quote_systemd_arg(arg: Any) -> str:
    """One systemd ``ExecStart`` argument, safe as exactly one argument.

    Double-quoted, with the three escapes systemd actually honours:

    * ``\\`` and ``"`` inside a quoted argument,
    * ``$`` doubled, because systemd DOES expand ``$VAR``/``${VAR}`` inside
      quotes — a target containing ``$HOME`` would otherwise be expanded by
      the service manager rather than passed to Phantom,
    * ``%`` doubled, because ``%`` introduces a systemd specifier.
    """
    text = str(arg)
    text = text.replace("\\", "\\\\").replace('"', '\\"')
    text = text.replace("$", "$$").replace("%", "%%")
    return f'"{text}"'


def quote_windows_arg(arg: Any) -> str:
    """One Windows command-line argument, following CommandLineToArgvW.

    Backslashes are only special immediately before a quote (they are doubled
    then, and a trailing run is doubled as well), which is the rule the Task
    Scheduler's own parser applies. Always quoted, so a target with a space or
    a semicolon stays one argument.
    """
    text = str(arg)
    out = ['"']
    pending = 0
    for ch in text:
        if ch == "\\":
            pending += 1
            continue
        if ch == '"':
            out.append("\\" * (pending * 2 + 1))
            out.append('"')
            pending = 0
            continue
        if pending:
            out.append("\\" * pending)
            pending = 0
        out.append(ch)
    if pending:
        out.append("\\" * (pending * 2))
    out.append('"')
    return "".join(out)


# ── systemd ────────────────────────────────────────────────────────────────

def render_systemd_unit(command: Sequence[str], *, working_dir: str,
                        name: str = "phantom-auto", user: bool = True,
                        restart: str = "on-failure",
                        restart_sec: int = 30) -> str:
    """A ``.service`` unit that starts ``command`` at boot and after a crash.

    ``Restart=on-failure`` and not ``always``: a run that FINISHES must not be
    started again (the agent decides when an engagement is over), while a run
    that dies must come back. A crash loop is bounded twice — systemd's
    ``StartLimitBurst`` stops the unit, and Phantom's persisted restart counter
    stops the relaunch from inside.

    ``WantedBy=default.target`` for a user unit, ``multi-user.target`` for a
    system one; ``network-online.target`` is only referenced in the system
    case, because a user instance has no such target and would refuse the unit.
    """
    name = _safe_name(name)
    command = [str(a) for a in command]
    if not command:
        raise ValueError("cannot render a service unit for an empty command")
    _assert_no_secret(command)
    exe = " ".join(quote_systemd_arg(a) for a in command)
    lines = [
        "[Unit]",
        f"Description=Phantom AUTO-MODE supervised run ({name})",
    ]
    if not user:
        lines += ["After=network-online.target",
                  "Wants=network-online.target"]
    lines += [
        # systemd's own crash-loop guard, in ADDITION to Phantom's persisted
        # counter: the manager stops the unit instead of restarting forever.
        "StartLimitIntervalSec=300",
        "StartLimitBurst=5",
        "",
        "[Service]",
        "Type=simple",
        f"WorkingDirectory={quote_systemd_arg(os.path.abspath(working_dir))}",
        # `sys.executable` is absolute, so PATH only has to let PHANTOM find
        # its own tools. PYTHONPATH keeps `-m phantom.main` importable even if
        # the unit's WorkingDirectory is ever moved.
        f"Environment=PYTHONPATH={working_dir}",
        f"ExecStart={exe}",
        f"Restart={restart}",
        f"RestartSec={int(restart_sec)}",
        "StandardOutput=journal",
        "StandardError=journal",
        "",
        "[Install]",
        f"WantedBy={'default.target' if user else 'multi-user.target'}",
        "",
    ]
    return "\n".join(lines)


# ── launchd ────────────────────────────────────────────────────────────────

_PLIST_DOCTYPE = ('<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
                  '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">')


def render_launchd_plist(command: Sequence[str], *, working_dir: str,
                         name: str = "com.phantom.auto",
                         restart_sec: int = 30,
                         logs_dir: str = "") -> str:
    """A LaunchAgent plist that runs ``command`` at load and after a failure.

    ``ProgramArguments`` is an ARRAY, so no quoting layer exists to get wrong:
    launchd execs the vector directly. ``KeepAlive`` is keyed on
    ``SuccessfulExit=false`` (the on-failure rule, not "always") and
    ``ThrottleInterval`` is the rescue for a crash loop.

    Built with ElementTree and then serialized, so every value is escaped by
    the XML library rather than by a template.
    """
    name = _safe_name(name)
    command = [str(a) for a in command]
    if not command:
        raise ValueError("cannot render a service unit for an empty command")
    _assert_no_secret(command)
    work = os.path.abspath(working_dir)
    logs = logs_dir or os.path.join(work, "data", "logs")

    root = ET.Element("plist", {"version": "1.0"})
    top = ET.SubElement(root, "dict")
    _plist_key(top, "Label", name)
    args = _plist_keyed(top, "ProgramArguments", "array")
    for arg in command:
        ET.SubElement(args, "string").text = arg
    _plist_key(top, "WorkingDirectory", work)
    _plist_key(top, "RunAtLoad", True)
    keep = _plist_keyed(top, "KeepAlive", "dict")
    _plist_key(keep, "SuccessfulExit", False)
    _plist_key(top, "ThrottleInterval", int(restart_sec))
    _plist_key(top, "StandardOutPath", os.path.join(logs, f"{name}.out.log"))
    _plist_key(top, "StandardErrorPath", os.path.join(logs, f"{name}.err.log"))
    ET.indent(root, space="  ")

    body = ET.tostring(root, encoding="unicode")
    return ('<?xml version="1.0" encoding="UTF-8"?>\n' + _PLIST_DOCTYPE
            + "\n" + body + "\n")


def _plist_keyed(parent: ET.Element, key: str, tag: str) -> ET.Element:
    """Append ``<key>key</key>`` plus an EMPTY ``<tag>`` container, in order.

    A plist dict is a flat run of key/value PAIRS, so a container appended
    without its key is an ORPHAN value: launchd reads it as garbage and a
    correct parser drops it. `ProgramArguments` and `KeepAlive` were emitted
    that way — the agent looked configured and started nothing, with the
    argument vector silently unattached from its key. The pairing lives in
    one helper now so it cannot be forgotten one container at a time.
    """
    ET.SubElement(parent, "key").text = key
    return ET.SubElement(parent, tag)


def _plist_key(parent: ET.Element, key: str, value: Any) -> None:
    """Append a plist ``<key>`` plus the typed element for ``value``."""
    ET.SubElement(parent, "key").text = key
    if isinstance(value, bool):
        ET.SubElement(parent, "true" if value else "false")
    elif isinstance(value, int):
        ET.SubElement(parent, "integer").text = str(value)
    else:
        ET.SubElement(parent, "string").text = str(value)


# ── Windows Task Scheduler ─────────────────────────────────────────────────

_TASK_NS = "http://schemas.microsoft.com/windows/2004/02/mit/task"


def render_windows_task_xml(command: Sequence[str], *, working_dir: str,
                            name: str = "PhantomAutoMode",
                            restart_sec: int = 30,
                            restart_count: int = 3) -> str:
    """A Task Scheduler definition for ``command``, imported with ``/xml``.

    Triggered at boot (with a short delay so the network stack is up), hidden
    (an auto-mode run has no window to show and would otherwise flash a
    console the operator cannot read), unlimited execution time (the whole
    point is a multi-day engagement), and restarted on failure.

    Built with ElementTree, like the plist, so the two XML formats cannot
    diverge in how they escape their values.
    """
    name = _safe_name(name)
    command = [str(a) for a in command]
    if not command:
        raise ValueError("cannot render a service unit for an empty command")
    _assert_no_secret(command)
    work = os.path.abspath(working_dir)

    # ElementTree writes `ns0:` prefixes unless a default prefix is
    # registered. The Task Scheduler schema is namespace-qualified and does
    # NOT accept a prefixed root, so the default is registered for this name.
    ET.register_namespace("", _TASK_NS)

    def tag(local: str) -> str:
        return f"{{{_TASK_NS}}}{local}"

    task = ET.Element(tag("Task"), {"version": "1.4"})
    reg = ET.SubElement(task, tag("RegistrationInfo"))
    ET.SubElement(reg, tag("Description")).text = (
        f"Phantom AUTO-MODE supervised run ({name})")
    triggers = ET.SubElement(task, tag("Triggers"))
    boot = ET.SubElement(triggers, tag("BootTrigger"))
    ET.SubElement(boot, tag("Enabled")).text = "true"
    ET.SubElement(boot, tag("Delay")).text = "PT1M"
    principals = ET.SubElement(task, tag("Principals"))
    principal = ET.SubElement(principals, tag("Principal"), {"id": "Author"})
    ET.SubElement(principal, tag("LogonType")).text = "InteractiveToken"
    ET.SubElement(principal, tag("RunLevel")).text = "LeastPrivilege"

    settings = ET.SubElement(task, tag("Settings"))
    ET.SubElement(settings, tag("MultipleInstancesPolicy")).text = "IgnoreNew"
    ET.SubElement(settings, tag("StartWhenAvailable")).text = "true"
    restart = ET.SubElement(settings, tag("RestartOnFailure"))
    ET.SubElement(restart, tag("Interval")).text = f"PT{max(1, int(restart_sec))}S"
    ET.SubElement(restart, tag("Count")).text = str(max(1, int(restart_count)))
    # no window: the run is a service, not a thing to watch
    ET.SubElement(settings, tag("Hidden")).text = "true"
    ET.SubElement(settings, tag("AllowStartOnDemand")).text = "true"
    # PT0S = no time limit. A default limit would kill a multi-day run.
    ET.SubElement(settings, tag("ExecutionTimeLimit")).text = "PT0S"
    ET.SubElement(settings, tag("DisallowStartIfOnBatteries")).text = "false"
    ET.SubElement(settings, tag("StopIfGoingOnBatteries")).text = "false"

    actions = ET.SubElement(task, tag("Actions"), {"Context": "Author"})
    exe = ET.SubElement(actions, tag("Exec"))
    ET.SubElement(exe, tag("Command")).text = command[0]
    if len(command) > 1:
        ET.SubElement(exe, tag("Arguments")).text = " ".join(
            quote_windows_arg(a) for a in command[1:])
    ET.SubElement(exe, tag("WorkingDirectory")).text = work

    ET.indent(task, space="  ")
    body = ET.tostring(task, encoding="unicode")
    return '<?xml version="1.0" encoding="UTF-16"?>\n' + body + "\n"


# ── paths, plans, install ──────────────────────────────────────────────────

def default_name(kind: str) -> str:
    """The unit name used when the operator passes none."""
    return _DEFAULT_NAMES.get(kind, f"phantom-{kind or 'auto'}")


def host_kind(host_os: str = "") -> str:
    """The unit format that applies to ``host_os`` (or to this machine)."""
    os_name = (host_os or HOST_OS).lower()
    for kind, systems in _OS_FOR_KIND.items():
        if os_name in systems:
            return kind
    return ""


def supported(kind: str, *, host_os: str = "") -> Tuple[bool, str]:
    """``(ok, reason)`` — is this unit format meaningful on ``host_os``?

    A refusal is a REASON, never an exception: the CLI prints it and exits
    non-zero, and nothing is written. Rendering a unit for another OS would
    produce a file that looks valid and cannot be installed, which is worse
    than saying no.
    """
    if kind not in KINDS:
        return False, (f"unknown service format {kind!r} "
                       f"(choose from {', '.join(KINDS)})")
    os_name = (host_os or HOST_OS).lower() or "unknown"
    if os_name not in _OS_FOR_KIND[kind]:
        return False, (f"a {kind} unit belongs to "
                       f"{'/'.join(_OS_FOR_KIND[kind])}, and this is "
                       f"{os_name} — use {host_kind(host_os) or 'nothing'} "
                       f"here")
    return True, ""


def service_path(kind: str, name: str, *, user: bool = True,
                 host_os: str = "") -> str:
    """Where the unit file belongs for ``kind`` on ``host_os``.

    The Windows definition is not an installed file at all (``schtasks``
    imports it and stores the task itself), so it is written under Phantom's
    own data directory: the file is the RECORD of what was registered, and
    ``--uninstall-service`` can still find it.
    """
    name = _safe_name(name)
    if kind == "systemd":
        if user:
            base = os.path.join(os.path.expanduser("~"), ".config",
                                "systemd", "user")
        else:
            base = "/etc/systemd/system"
        return os.path.join(base, f"{name}.service")
    if kind == "launchd":
        return os.path.join(os.path.expanduser("~"), "Library",
                            "LaunchAgents", f"{name}.plist")
    if kind == "schtasks":
        from phantom.utils.paths import data_dir
        return os.path.join(data_dir(), "services", f"{name}.xml")
    raise ValueError(f"unknown service format {kind!r}")


def render_unit(kind: str, command: Sequence[str], *, working_dir: str,
                name: str = "", user: bool = True,
                restart: str = "on-failure", restart_sec: int = 30,
                restart_count: int = 3) -> str:
    """Render the unit for ``kind`` — the single dispatch the CLI uses."""
    unit_name = _safe_name(name or default_name(kind))
    if kind == "systemd":
        return render_systemd_unit(command, working_dir=working_dir,
                                  name=unit_name, user=user, restart=restart,
                                  restart_sec=restart_sec)
    if kind == "launchd":
        return render_launchd_plist(command, working_dir=working_dir,
                                    name=unit_name, restart_sec=restart_sec)
    if kind == "schtasks":
        return render_windows_task_xml(command, working_dir=working_dir,
                                       name=unit_name,
                                       restart_sec=restart_sec,
                                       restart_count=restart_count)
    raise ValueError(f"unknown service format {kind!r}")


def activate_hint(kind: str, name: str, *, path: str = "",
                  user: bool = True) -> str:
    """The command the OPERATOR runs to activate the unit.

    Returned as text on purpose: enabling a boot-level service is the one step
    that must stay visible, so this module never runs it.
    """
    unit = path or service_path(kind, name or default_name(kind), user=user)
    if kind == "systemd":
        prefix = "systemctl --user" if user else "sudo systemctl"
        return (f"{prefix} daemon-reload && {prefix} enable --now "
                f"{os.path.basename(unit)}")
    if kind == "launchd":
        return f"launchctl load -w {unit}"
    if kind == "schtasks":
        return f'schtasks /create /xml "{unit}" /tn "{name or default_name(kind)}" /f'
    raise ValueError(f"unknown service format {kind!r}")


def plan_service(kind: str, command: Sequence[str], *, working_dir: str,
                 name: str = "", user: bool = True,
                 restart: str = "on-failure", restart_sec: int = 30,
                 restart_count: int = 3, host_os: str = "") -> Dict[str, str]:
    """``{kind, name, path, content, hint, user}`` — render WITHOUT writing.

    The refusal for a format that does not belong to this OS happens HERE, so
    a caller that only plans can never end up with a file for the wrong
    platform.
    """
    ok, reason = supported(kind, host_os=host_os)
    if not ok:
        raise ValueError(reason)
    unit_name = _safe_name(name or default_name(kind))
    content = render_unit(kind, command, working_dir=working_dir,
                          name=unit_name, user=user, restart=restart,
                          restart_sec=restart_sec,
                          restart_count=restart_count)
    path = service_path(kind, unit_name, user=user, host_os=host_os)
    # The Task Scheduler reads its definition as UTF-16, and the declaration
    # inside the document has to match the bytes on disk or the import rejects
    # the file. The plist and the systemd unit are UTF-8 (systemd requires it;
    # nobody reads a plist as UTF-16).
    encoding = "utf-16" if kind == "schtasks" else "utf-8"
    return {"kind": kind, "name": unit_name, "path": path,
            "content": content, "user": "1" if user else "0",
            "encoding": encoding,
            # WHAT this unit is (the exact invocation) and WHICH bytes it is
            # (so a pre-existing file can be told apart from this one).
            "digest": invocation_digest(command),
            "content_digest": content_digest(content, encoding),
            "hint": activate_hint(kind, unit_name, path=path, user=user)}


def existing_service(path: str, content: str = "",
                     encoding: str = "utf-8") -> Tuple[str, bool]:
    """``(digest, same)`` for a file already at ``path``.

    ``("", False)`` when nothing is there. ``same`` is True only when the file
    is byte-identical to what this invocation would render — that is the
    difference between "re-running my own install" (a no-op) and "overwriting
    whatever was already there", which this module refuses to do silently.
    """
    found = file_digest(path)
    if not found:
        return "", False
    return found, found == content_digest(content, encoding)


def install_service(plan: Dict[str, str], *, overwrite: bool = False) -> str:
    """Write a rendered plan to disk and return the path.

    The ONLY function in this module that touches the filesystem, and it
    refuses an empty plan instead of writing a half-unit. It creates parents
    (``~/.config/systemd/user`` may not exist yet) and leaves the file
    readable: the operator is meant to review it.

    Two refusals the operator asked for (audit P2, "rete di sicurezza"):

    * a DIFFERENT unit already at that path is not overwritten — the file may
      be another engagement's, or the operator's hand-edited copy, and a
      framework that clobbers a boot-level file in silence is unauditable.
      Re-installing the SAME content is idempotent (and still verified);
      replacing it is explicit (`overwrite=True`);
    * the write is READ BACK and hashed: if the bytes on disk are not the
      bytes that were rendered (a short write, a wrong encoding), this raises
      instead of leaving a half-unit that the OS will parse and reject later.
    """
    path = str((plan or {}).get("path") or "")
    content = (plan or {}).get("content") or ""
    if not path or not content:
        raise ValueError("refusing to install an empty service plan")
    encoding = (plan or {}).get("encoding") or "utf-8"
    found, same = existing_service(path, content, encoding)
    if found and not same and not overwrite:
        raise ValueError(
            f"a DIFFERENT service definition already exists at {path} "
            f"(sha256 {found[:16]}… vs {content_digest(content, encoding)[:16]}… "
            f"for this invocation): refusing to overwrite it — review it, "
            f"remove it with --uninstall-service, or re-run with overwrite")
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding=encoding, newline="\n") as handle:
        handle.write(content)
    try:
        os.chmod(path, 0o644)
    except OSError:
        # Windows has no POSIX mode bits; the write itself already succeeded.
        pass
    written = file_digest(path)
    expected = content_digest(content, encoding)
    if written != expected:
        raise ValueError(
            f"the file written to {path} is not what was rendered "
            f"(sha256 {written[:16] or 'unreadable'}… != {expected[:16]}…) — "
            f"the definition is untrustworthy, remove it")
    return path


def uninstall_service(path: str) -> bool:
    """Remove a unit file. True when it is gone, False when it never existed.

    "Verifiable" is literal: after ``os.remove`` the path is checked again, and
    a file still standing there is an ERROR rather than a success message —
    "removed" that leaves a unit behind is worse than a refusal.
    """
    target = str(path or "")
    if not target:
        raise ValueError("refusing to uninstall without a path")
    try:
        os.remove(target)
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise ValueError(f"cannot remove {target}: {exc}") from exc
    if os.path.exists(target):
        raise ValueError(f"{target} still exists after removal — the unit was "
                         f"NOT uninstalled")
    return True
