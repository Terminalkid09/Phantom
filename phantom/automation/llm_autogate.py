"""llm_autogate.py — who accepts a model proposal when nobody is watching?

The operator-facing gate (`llm_proposals`) answers: "the model may ask, a human
decides". Auto-mode has no human in the loop — that is the whole point of
auto-mode, and stopping the run to ask "may I run nmap?" after the operator set
a target and walked away would be a worse product than not proposing at all.
So the DECIDER changes, not the CONTRACT:

    the model proposes  ->  a DETERMINISTIC policy accepts or refuses
                        ->  an accepted proposal runs through the same gated
                            executor as any capability (scope, tool, noise)
                        ->  every decision is journalled with its REASON, so
                            the operator can review afterwards what the model
                            wanted and why the algorithm said no.

`decide()` is the policy and it is a PURE function of (command, context): no
network, no state, no model. That is what makes it auditable and testable, and
it is why auto-mode acceptance can be trusted: the same input always gets the
same verdict, with a reason string that names the rule that fired.

The policy is deliberately asymmetric — it fails CLOSED. Anything it does not
explicitly recognise as a bounded, non-destructive action is refused, because a
refused proposal costs one opportunity while a wrong acceptance can destroy
evidence, the target or the operator's own machine. Refusals are cheap and
recorded; that is the trade this module makes in the operator's absence.

THREE TIERS, and the difference between them is the whole policy:

* `DESTRUCTIVE`   — never accepted, in ANY posture. Wiping shadow copies,
                    killing the box, installing software on the operator's
                    machine, locking the operator out. Aggressive means LOUD,
                    never DAMAGING: `--aggressive` does not unlock this tier.
* AGGRESSIVE flags (`DANGEROUS_FLAGS`) — refused by default, accepted when
                    the operator chose `--aggressive` (that flag exists
                    precisely to buy these techniques). Still subject to the
                    allowlist, the scope and the destructive checks.
* everything else   — allowlisted enumeration, accepted.

STRUCTURE is checked too, not just the first word: a compound command must
have EVERY element pass, and the right-hand side of a pipe may additionally be
a read-only filter (`PIPELINE_HELPERS`) — which is what keeps
`curl … | grep -i server` a normal enumeration pipeline while `… | xargs`
(it executes its arguments) and `… | sh` stay refused. The splitter is the
SAME one the executor uses (`phantom.core.safe_exec.split_operators`), so
validation and execution can never disagree about what a command means.
"""

from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

ACCEPTED = "accepted"
REFUSED = "refused"

# Programs auto-mode may run WITHOUT asking: read-only enumeration/recon. The
# list is a decision, not an accident — every entry is a tool the manual shell
# already offers and whose damage is bounded to "it makes noise".
ALLOWED_PROGRAMS = frozenset((
    "nmap", "masscan", "dig", "host", "nslookup", "whois", "traceroute",
    "curl", "wget", "openssl", "sherlock", "subfinder", "amass", "assetfinder",
    "theharvester", "dnsrecon", "gobuster", "ffuf", "feroxbuster", "nikto",
    "whatweb", "wafw00f", "enum4linux", "smbclient", "smbmap", "rpcclient",
    "ldapsearch", "kerbrute", "getent", "nxc", "crackmapexec", "sqlmap",
    "wpscan", "showmount", "snmpwalk", "onesixtyone", "ike-scan", "nbtscan",
    "arp-scan", "avahi-browse", "ssh-keyscan", "testssl.sh", "sslscan",
    "hydra", "medusa", "ncrack", "john", "hashcat", "wordlists",
))

# Programs that are NEVER auto-accepted, whatever the model argues: they
# destroy data, take the machine down, remove the operator's own access, or
# install software. `why` is the reason recorded in the journal.
DESTRUCTIVE = {
    "rm": "destroys data on the target or the operator's machine",
    "shred": "destroys data irreversibly",
    "mkfs": "reformats a filesystem",
    "mkfs.ext4": "reformats a filesystem",
    "dd": "raw write: can destroy a disk",
    "shutdown": "takes a machine down",
    "reboot": "takes a machine down",
    "halt": "takes a machine down",
    "poweroff": "takes a machine down",
    "init": "changes the machine's runlevel",
    "userdel": "removes an account (the operator's own access, possibly)",
    "groupdel": "removes a group",
    "passwd": "changes a credential",
    "chpasswd": "changes credentials in bulk",
    "iptables": "can lock the operator out of the target",
    "nft": "can lock the operator out of the target",
    "ufw": "can lock the operator out of the target",
    "systemctl": "stops services (and can stop the C2 listener)",
    "service": "stops services",
    "kill": "kills processes",
    "pkill": "kills processes indiscriminately",
    "killall": "kills processes indiscriminately",
    "taskkill": "kills processes",
    "vssadmin": "deletes shadow copies (destroys recovery data)",
    "wbadmin": "deletes backups",
    "cipher": "wipes free space",
    "bcdedit": "can make a machine unbootable",
    "bcdboot": "can make a machine unbootable",
    "format": "reformats a volume",
    "diskpart": "repartitions a disk",
    "reg": "edits the registry in place",
    "netsh": "edits firewall/network config in place",
    "net": "changes accounts/shares/services",
    "dsmod": "modifies directory objects",
    "ldapmodify": "modifies directory objects",
    "apt": "installs software on the OPERATOR's machine",
    "apt-get": "installs software on the operator's machine",
    "yum": "installs software on the operator's machine",
    "dnf": "installs software on the operator's machine",
    "pacman": "installs software on the operator's machine",
    "zypper": "installs software on the operator's machine",
    "brew": "installs software on the operator's machine",
    "winget": "installs software on the operator's machine",
    "choco": "installs software on the operator's machine",
    "pip": "installs software on the operator's machine",
    "pip3": "installs software on the operator's machine",
    "npm": "installs software on the operator's machine",
    "gem": "installs software on the operator's machine",
    "sudo": "requires a privilege decision the policy cannot make",
    "su": "requires a privilege decision the policy cannot make",
    "doas": "requires a privilege decision the policy cannot make",
    "runas": "requires a privilege decision the policy cannot make",
}

# Handing a string to an interpreter is a remote-code surface: a proposal that
# pipes into one of these is not an enumeration command, it is "run whatever
# comes back", which no policy can review in advance.
INTERPRETERS = frozenset((
    "sh", "bash", "zsh", "dash", "ksh", "csh", "tcsh", "fish", "python",
    "python3", "perl", "ruby", "node", "php", "powershell", "pwsh", "cmd",
    "cmd.exe", "eval", "exec", "source", ".",
))

_PIPE_TO_INTERPRETER = re.compile(
    r"\|\s*(?:sudo\s+)?(" + "|".join(re.escape(p) for p in INTERPRETERS) + r")\b",
    re.IGNORECASE)
_REDIRECT_WRITE = re.compile(r">\s*(?:/[A-Za-z]|~|\$|/etc|/boot|/usr|/var|C:)", re.IGNORECASE)

# ...but the executor itself WHITELISTS a handful of redirects
# (`phantom.core.safe_exec._SAFE_REDIRECTS`): `2>/dev/null` is how every
# module run silences its own stderr, and `2>&1` merges the streams. Those are
# not "writing into a system path" — refusing them would refuse the run's own
# vocabulary and stall a chain for no safety gain, so they are stripped
# BEFORE the check. The pattern is built from the executor's own tuple instead
# of being copied, so the gate and the executor cannot drift apart on which
# redirect is benign; if that import ever fails, the regex matches nothing and
# the check stays as strict as before (fail closed).
_SAFE_REDIRECT_RE: Optional[re.Pattern] = None


def _safe_redirect_re() -> re.Pattern:
    """Regex of redirects the EXECUTOR whitelists (built once, lazily)."""
    global _SAFE_REDIRECT_RE
    if _SAFE_REDIRECT_RE is None:
        try:
            from phantom.core.safe_exec import _SAFE_REDIRECTS
            alt = "|".join(re.escape(s) for s in _SAFE_REDIRECTS)
            _SAFE_REDIRECT_RE = re.compile(r"(?<![>\w])(?:" + alt + r")")
        except Exception:                      # pragma: no cover - defensive
            _SAFE_REDIRECT_RE = re.compile(r"(?!)")     # matches nothing
    return _SAFE_REDIRECT_RE

# `--` flags that turn a read-only tool into an AGGRESSIVE one: refused in
# the default posture, accepted under `--aggressive` (tier 2 above). These are
# not destructive — `curl -F` uploads a file, `nmap --script` probes for a
# vulnerability — so they are exactly what the aggressive posture is for.
DANGEROUS_FLAGS: Dict[str, Tuple[str, ...]] = {
    "nmap": ("--script",),
    "sqlmap": ("--os-shell", "--os-pwn", "--os-cmd", "--file-write",
               "--file-dest", "--sql-shell", "--os-smbrelay", "--priv-esc"),
    "hydra": (),
    "curl": ("--upload-file", "-T", "--data-binary", "--form", "-F"),
    "wget": ("--post-data", "--post-file"),
    "smbclient": ("-c",),
    "net": (),
}
# flags that mean "change the remote state" regardless of the tool. `-w` is
# deliberately NOT here: on `curl -w` it prints timing, on `gobuster -w` it
# takes a wordlist — refusing it would refuse half of the recon vocabulary.
WRITE_FLAGS = ("--delete", "--remove", "--overwrite", "--truncate",
               "--set", "--create")

# Read-only filters that may sit on the RIGHT-hand side of a PIPE. A pipe is
# how enumeration actually reads its own output (`curl … | grep -i server`,
# `… | jq .items`), so refusing every pipe would refuse the vocabulary the
# model needs — but the right-hand side is also where "read-only" stops being
# true. Every entry below only READS stdin.
#
# Deliberately ABSENT, and this is the point of the list: `xargs` (it executes
# its arguments), `env`, `find` (it can `-exec`), and every interpreter (which
# `INTERPRETERS` already refuses wherever it appears after a pipe).
PIPELINE_HELPERS = frozenset((
    "grep", "egrep", "fgrep", "awk", "sed", "sort", "uniq", "cut", "tr",
    "head", "tail", "wc", "jq", "column", "strings", "xxd", "base64",
    "rev", "nl", "tac", "diff", "md5sum", "sha1sum", "sha256sum",
))


def _flag_present(argv: Sequence[str], flag: str) -> bool:
    """Is ``flag`` one of this element's OWN arguments (`--x` or `--x=v`)?

    Checked per element instead of over the whole line: a flag belongs to the
    program that carries it, so `nmap … && curl -F …` must not be judged by
    nmap's flag list nor by curl's position.
    """
    for token in argv:
        if token == flag or token.startswith(flag + "="):
            return True
    return False


def _program_of_argv(argv: Sequence[str]) -> str:
    """The program of ONE parsed element: leading word, env prefixes skipped."""
    index = 0
    while index < len(argv) and "=" in argv[index] \
            and not argv[index].startswith(("/", ".")):
        index += 1
    if index >= len(argv):
        return ""
    return os.path.basename(argv[index]).lower()


def _elements(text: str) -> List[Tuple[str, List[str], str]]:
    """[(program, argv, joining_operator)] for every element of the command.

    Reuses the SHARED splitter (`phantom.core.safe_exec.split_operators`) the
    executor parses with, so the gate and the execution agree on the meaning
    of `;`/`&&`/`||`/`|` AND on quotes: a separator inside quotes
    (`msfconsole -x "use a; run"`) is DATA, not a second command. Balanced
    quotes are required; anything the parser cannot model (unbalanced quote,
    stray operator) raises and the caller refuses.
    """
    from phantom.core.safe_exec import split_operators
    segments, separators = split_operators(text)
    out: List[Tuple[str, List[str], str]] = []
    for index, segment in enumerate(segments):
        if not segment:
            continue
        try:
            argv = shlex.split(segment, posix=True)
        except ValueError as exc:
            raise ValueError(f"unparseable segment (check quotes): {exc}") from exc
        if not argv:
            continue
        if index == 0:
            joined = ""
        elif index - 1 < len(separators):
            joined = separators[index - 1]
        else:
            joined = ";"
        out.append((_program_of_argv(argv), argv, joined))
    return out


@dataclass
class Decision:
    """The deterministic verdict on one proposal, with the rule that fired."""

    accepted: bool
    reason: str
    program: str = ""
    category: str = ""

    @property
    def verdict(self) -> str:
        return ACCEPTED if self.accepted else REFUSED

    def to_dict(self) -> Dict[str, Any]:
        return {"verdict": self.verdict, "reason": self.reason,
                "program": self.program, "category": self.category}


def program_of(command: str) -> str:
    """The program a command would run: first word, path stripped."""
    text = (command or "").strip()
    if not text:
        return ""
    try:
        parts = shlex.split(text, posix=True)
    except ValueError:
        parts = text.split()
    if not parts:
        return ""
    first = parts[0]
    # env-var prefixes (`FOO=1 tool`) are not the program
    index = 0
    while index < len(parts) and "=" in parts[index] and not parts[index].startswith(("/", ".")):
        index += 1
    if index < len(parts):
        first = parts[index]
    return os.path.basename(first).lower()


def decide(command: str, *, scope: Optional[Sequence[str]] = None,
           paranoid: bool = False,
           strict: bool = False,
           aggressive: bool = False,
           extra_allowed: Optional[Sequence[str]] = None,
           is_in_scope: Optional[Any] = None) -> Decision:
    """Accept or refuse ONE model proposal, deterministically.

    Order matters: the destructive check runs before the allowlist, because
    "it is on the allowlist" must never override "it destroys something"
    (several tools appear in both lists once a dangerous flag is added).
    `paranoid` and `strict` narrow the policy further — in those modes only a
    bare, allowlisted, single command survives. `aggressive` is the operator's
    POSTURE: it widens the technique set (the AGGRESSIVE flags) and nothing
    else — `DESTRUCTIVE` is refused in every posture, because aggressive means
    loud, never damaging.
    """
    text = (command or "").strip()
    if not text:
        return Decision(False, "empty command")

    # 0. the gate must be able to READ it: one line, no embedded newline
    if "\n" in text or "\r" in text:
        return Decision(False, "multi-line: not a single reviewable command")

    program = program_of(text)
    if not program:
        return Decision(False, "no program in the proposal")

    # 0.5 substitution: the shell would run something the policy never saw
    for token in ("`", "$(", "${"):
        if token in text:
            return Decision(False, "command substitution is not reviewable",
                            program, "remote-code")

    # 1. hard refusals first — identical in EVERY posture
    if program in DESTRUCTIVE:
        return Decision(False, DESTRUCTIVE[program], program, "destructive")
    if _PIPE_TO_INTERPRETER.search(text):
        return Decision(False, "pipes into an interpreter (unreviewable code)",
                        program, "remote-code")
    if re.search(r"(?:^|\s)-exec(?:dir)?(?:\s|$)", text):
        return Decision(False, "-exec runs a command per match "
                               "(unreviewable code)", program, "remote-code")
    lowered = text.lower()
    for token in ("/dev/sd", "/dev/nvme", "/dev/zero", "/dev/urandom"):
        if token in lowered:
            return Decision(False, f"writes to a raw device ({token})",
                            program, "destructive")
    if _REDIRECT_WRITE.search(_safe_redirect_re().sub(" ", text)):
        return Decision(False, "redirects output into a system path",
                        program, "destructive")
    for flag in WRITE_FLAGS:
        if re.search(r"(?:^|\s)" + re.escape(flag) + r"(?:\s|=|$)", text):
            return Decision(False, f"write/delete flag '{flag}' in a proposal",
                            program, "destructive")

    # the STRUCTURE, parsed by the splitter the executor itself uses: a
    # command the parser cannot model fails CLOSED like everything else here
    try:
        elements = _elements(text)
    except Exception as exc:
        return Decision(False, f"unparseable command ({exc})", program,
                        "unparseable")

    # 2. tool-specific AGGRESSIVE flags: refused in the default posture,
    #    accepted under --aggressive — still subject to the allowlist, the
    #    scope and the destructive checks below them.
    if not aggressive:
        for pid, argv, _sep in elements:
            for flag in DANGEROUS_FLAGS.get(pid, ()):  # type: ignore[arg-type]
                if _flag_present(argv, flag):
                    return Decision(
                        False, f"{pid} {flag} needs the aggressive posture",
                        pid, "dangerous-flag")

    # 3. allowlist (narrowed in paranoid/strict: no extra programs)
    allowed = set(ALLOWED_PROGRAMS)
    if not (paranoid or strict):
        allowed |= {p.lower() for p in (extra_allowed or ())}
    if program not in allowed:
        return Decision(False, f"'{program}' is not on the auto-mode allowlist",
                        program, "not-allowlisted")

    # 4. EVERY element must pass, not only the first: `;`/`&&`/`||`/`|` used
    #    to be able to smuggle a program past the check. The right-hand side
    #    of a PIPE may also be a read-only filter, which is what keeps
    #    `curl … | grep -i server` usable while `… | xargs` stays refused.
    for index, (pid, _argv, joined) in enumerate(elements):
        if index == 0 or not pid:
            continue
        if pid in DESTRUCTIVE:
            return Decision(False, DESTRUCTIVE[pid], pid, "destructive")
        if joined == "|":
            if pid in PIPELINE_HELPERS or pid in allowed:
                continue
            return Decision(False, f"'{pid}' is not an allowlisted "
                                   f"pipeline filter", pid, "not-allowlisted")
        if pid not in allowed:
            return Decision(False, f"'{pid}' is not on the auto-mode allowlist "
                                   f"(chained command)", pid, "not-allowlisted")

    # 5. chaining: strict mode refuses anything compound, so the reviewed
    #    command is exactly the one that runs
    if len(elements) > 1 and (paranoid or strict):
        return Decision(False, "compound command in strict/paranoid mode",
                        program, "compound")

    # 6. the engagement scope, on the hosts NAMED IN THE COMMAND
    if scope:
        from phantom.automation.llm_proposals import out_of_scope_hosts
        checker = is_in_scope
        bad = out_of_scope_hosts(text, scope, check=checker)
        if bad:
            return Decision(False, "out of scope: " + ", ".join(bad),
                            program, "out-of-scope")
    return Decision(True, f"allowlisted enumeration tool '{program}'",
                    program, "allowlisted")


def apply_decisions(proposals: Sequence[Any], *,
                    decided_by: str = "auto-policy",
                    queue: Optional[Any] = None, **context: Any
                    ) -> Tuple[List[Any], List[Tuple[Any, Decision]]]:
    """Decide a whole batch: accept/refuse in the queue, return both lists.

    The queue records the DECIDER (`auto-policy`), so the journal and the CLI
    distinguish an operator decision from an algorithmic one — which is the
    only way a human can afterwards audit what the run did on its own.

    `**context` is forwarded to :func:`decide` verbatim, so the CALLER's
    posture applies to every proposal in the batch: `aggressive=True` accepts
    the aggressive tier, `strict`/`paranoid` narrow it back to bare
    allowlisted commands, and `scope` still bounds the hosts touched.
    """
    from phantom.automation import llm_proposals
    target_queue = queue if queue is not None else llm_proposals.queue
    accepted: List[Any] = []
    refused: List[Tuple[Any, Decision]] = []
    for proposal in proposals or []:
        decision = decide(getattr(proposal, "command", ""), **context)
        if decision.accepted:
            ok, _message = target_queue.accept(proposal.id, decided_by=decided_by)
            if ok:
                accepted.append(proposal)
                continue
            refused.append((proposal, Decision(
                False, "queue refused the acceptance", decision.program,
                "queue")))
            continue
        target_queue.refuse(proposal.id, decision.reason, decided_by=decided_by)
        refused.append((proposal, decision))
    return accepted, refused


def render(accepted: Sequence[Any], refused: Sequence[Tuple[Any, Decision]],
           limit: int = 6) -> str:
    """One-line-per-decision summary for the run timeline."""
    lines: List[str] = []
    for proposal in list(accepted)[:limit]:
        lines.append(f"auto-accepted: $ {proposal.command}")
    for proposal, decision in list(refused)[:limit]:
        lines.append(f"auto-refused ({decision.category}): $ "
                     f"{proposal.command} — {decision.reason}")
    return "\n".join(lines)
