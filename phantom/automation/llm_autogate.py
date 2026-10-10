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

# `--` flags that turn a read-only tool into a destructive one.
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
           extra_allowed: Optional[Sequence[str]] = None,
           is_in_scope: Optional[Any] = None) -> Decision:
    """Accept or refuse ONE model proposal, deterministically.

    Order matters: the destructive check runs before the allowlist, because
    "it is on the allowlist" must never override "it destroys something"
    (several tools appear in both lists once a dangerous flag is added).
    `paranoid` and `strict` narrow the policy further — in those modes only a
    bare, allowlisted, single command survives.
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

    # 1. hard refusals first
    if program in DESTRUCTIVE:
        return Decision(False, DESTRUCTIVE[program], program, "destructive")
    if _PIPE_TO_INTERPRETER.search(text):
        return Decision(False, "pipes into an interpreter (unreviewable code)",
                        program, "remote-code")
    lowered = text.lower()
    for token in ("/dev/sd", "/dev/nvme", "/dev/zero", "/dev/urandom"):
        if token in lowered:
            return Decision(False, f"writes to a raw device ({token})",
                            program, "destructive")
    if _REDIRECT_WRITE.search(text):
        return Decision(False, "redirects output into a system path",
                        program, "destructive")
    for flag in WRITE_FLAGS:
        if re.search(r"(?:^|\s)" + re.escape(flag) + r"(?:\s|=|$)", text):
            return Decision(False, f"write/delete flag '{flag}' in a proposal",
                            program, "destructive")

    # 2. tool-specific dangerous flags
    for flag in DANGEROUS_FLAGS.get(program, ()):  # type: ignore[arg-type]
        if re.search(r"(?:^|\s)" + re.escape(flag) + r"(?:\s|=|$)", text):
            return Decision(False, f"{program} {flag} is not enumeration",
                            program, "dangerous-flag")

    # 3. allowlist (narrowed in paranoid/strict: no extra programs)
    allowed = set(ALLOWED_PROGRAMS)
    if not (paranoid or strict):
        allowed |= {p.lower() for p in (extra_allowed or ())}
    if program not in allowed:
        return Decision(False, f"'{program}' is not on the auto-mode allowlist",
                        program, "not-allowlisted")

    # 4. chaining: strict mode refuses anything compound, so the reviewed
    #    command is exactly the one that runs
    chained = bool(re.search(r"[;&|]{1,2}(?![&|])", text)) or bool(
        re.search(r"\|\s*\S", text))
    if chained and (paranoid or strict):
        return Decision(False, "compound command in strict/paranoid mode",
                        program, "compound")
    if chained and re.search(r"(?:;|&&|\|\|)\s*\S", text):
        # a second command can smuggle anything past the program check
        second = re.split(r"(?:;|&&|\|\|)", text, maxsplit=1)
        if len(second) > 1 and program_of(second[1]) in DESTRUCTIVE:
            return Decision(False, "chains into a destructive command",
                            program, "destructive")

    # 5. the engagement scope, on the hosts NAMED IN THE COMMAND
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
