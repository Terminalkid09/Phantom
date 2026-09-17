"""safe_exec.py — argv-based execution for the operator API surface.

The API is NOT a trusted boundary: the renderer is a browser process, and a
compromised one can send any string to `/api/modules/*/run` or
`/api/backend/run`. Filtering shell *strings* is not a boundary — the former
implementation checked only the leading binary, so `nmap x; rm -rf ~` ran
under `shell=True`.

This module makes the parsed structure authoritative:

    parse(cmd)         -> segments as ARGV LISTS (quote-aware, no shell)
    run_local(parsed)  -> executes each segment with shell=False, wiring
                          pipes natively and honouring only the two benign
                          redirects the modules actually emit
                          (`2>/dev/null`, `2>&1`)
    to_shell_string()  -> re-serialises a PARSED pipeline with per-token
                          quoting, for backends that must receive a string
                          (WSL2 `bash -lc`, remote ssh) — the raw operator
                          string never reaches those shells.

Anything the parser cannot represent as plain argv (command substitution,
backticks, `&&` chains beyond our segments, unknown redirections) is
REFUSED rather than escaped.
"""

from __future__ import annotations

import os
import shlex
import subprocess
import time
from dataclasses import dataclass, field
from typing import List, Optional

from phantom.core.executor import QuietResult

# Shell control operators the parser understands as STRUCTURE.
_PIPE = "|"
_AND = "&&"
_OR = "||"
_SEMI = ";"

# Redirects the modules legitimately emit, and nothing else.
_SAFE_REDIRECTS = ("2>/dev/null", "2>&1", ">/dev/null", "1>/dev/null")


class UnsafeCommand(ValueError):
    """The command cannot be represented as argv (or is outright refused)."""


@dataclass
class ParsedPipeline:
    source: str
    segments: List[List[str]] = field(default_factory=list)
    # parallel to segments: which join operator preceded each segment
    separators: List[str] = field(default_factory=list)
    # per-segment flags
    stderr_devnull: List[bool] = field(default_factory=list)
    stdout_devnull: List[bool] = field(default_factory=list)
    stderr_to_stdout: List[bool] = field(default_factory=list)


def _strip_trailing_comment(cmd: str) -> str:
    """Module commands carry `  # reason` comments — drop them before parsing
    so the comment never becomes part of the token stream."""
    out: List[str] = []
    quote: Optional[str] = None
    i = 0
    while i < len(cmd):
        ch = cmd[i]
        if quote:
            out.append(ch)
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in "\"'":
            quote = ch
            out.append(ch)
            i += 1
            continue
        if ch == "#":
            break
        out.append(ch)
        i += 1
    return "".join(out).strip()


def split_operators(cmd: str) -> tuple[List[str], List[str]]:
    """Split on control operators that appear OUTSIDE quotes.

    Returns (segments, separators). Quoted separators — e.g.
    `msfconsole -x "use a; run"` — stay inside their segment: they are
    ARGUMENTS, not new commands.
    """
    segments: List[str] = []
    separators: List[str] = []
    buf: List[str] = []
    quote: Optional[str] = None
    i = 0
    while i < len(cmd):
        ch = cmd[i]
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in "\"'":
            quote = ch
            buf.append(ch)
            i += 1
            continue
        two = cmd[i:i + 2]
        if two in ("&&", "||"):
            segments.append("".join(buf))
            separators.append(two)
            buf = []
            i += 2
            continue
        if ch in ";\n":
            segments.append("".join(buf))
            separators.append(_SEMI)
            buf = []
            i += 1
            continue
        if ch == "|":
            # `||` was handled above; a single `|` is a pipe
            segments.append("".join(buf))
            separators.append(_PIPE)
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    if quote:
        raise UnsafeCommand("unbalanced quote in command")
    segments.append("".join(buf))
    return [s.strip() for s in segments], separators


def parse(cmd: str) -> ParsedPipeline:
    """Parse a module command into argv segments. Raises UnsafeCommand."""
    raw = (cmd or "").strip()
    if not raw:
        raise UnsafeCommand("empty command")
    # Nested execution the parser never sees. Modules never generate these.
    if "`" in raw or "$(" in raw or "${" in raw:
        raise UnsafeCommand("command substitution is not allowed")
    stripped = _strip_trailing_comment(raw)
    segments, separators = split_operators(stripped)
    # the comment strip can leave the trailing separator list one short
    if len(separators) >= len(segments):
        separators = separators[:len(segments) - 1]
    parsed = ParsedPipeline(source=raw)
    for seg in segments:
        if not seg:
            raise UnsafeCommand("empty pipe segment")
        try:
            argv = shlex.split(seg, posix=True)
        except ValueError as exc:
            raise UnsafeCommand(f"unparseable command (check quotes): {exc}") from exc
        if not argv:
            raise UnsafeCommand("empty segment")
        # peel recognised redirects off the tail
        stderr_null = stdout_null = stderr_stdout = False
        while argv:
            tail = argv[-1]
            if tail == "2>/dev/null":
                stderr_null = True
            elif tail == "2>&1":
                stderr_stdout = True
            elif tail in (">/dev/null", "1>/dev/null"):
                stdout_null = True
            else:
                break
            argv.pop()
        if not argv:
            raise UnsafeCommand("segment is only a redirect")
        # any OTHER shell metacharacter reaching argv means the parser
        # mis-modelled the command: refuse instead of escaping
        for token in argv:
            if token in (";", "&&", "||", "|", "&", ">", ">>", "<", "<<"):
                raise UnsafeCommand(f"unsupported shell operator: {token}")
        parsed.segments.append(argv)
        parsed.stderr_devnull.append(stderr_null)
        parsed.stdout_devnull.append(stdout_null)
        parsed.stderr_to_stdout.append(stderr_stdout)
    parsed.separators = separators
    if not parsed.segments:
        raise UnsafeCommand("no executable segment")
    return parsed


def to_shell_string(parsed: ParsedPipeline) -> str:
    """Re-serialise a PARSED pipeline with per-token quoting.

    Used for backends that must receive a string (WSL2 `bash -lc`, remote
    ssh): every token is quoted, so nothing the caller sent can become
    shell syntax on the far side.
    """
    parts: List[str] = []
    for i, argv in enumerate(parsed.segments):
        if i:
            parts.append(parsed.separators[i - 1] if i - 1 < len(parsed.separators)
                         else _SEMI)
        parts.append(shlex.join(argv))
        if parsed.stdout_devnull[i]:
            parts.append(">/dev/null")
        if parsed.stderr_to_stdout[i]:
            parts.append("2>&1")
        elif parsed.stderr_devnull[i]:
            parts.append("2>/dev/null")
    return " ".join(parts)


def _spawn(argv: List[str], stdin, stdout, stderr):
    kwargs = {}
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True
    return subprocess.Popen(argv, stdin=stdin, stdout=stdout, stderr=stderr,
                            text=True, **kwargs)


def run_local(parsed: ParsedPipeline, timeout: float = 120.0) -> QuietResult:
    """Execute a parsed pipeline with shell=False.

    Pipes are wired natively; `;`/`&&`/`||` run sequentially with the usual
    short-circuit semantics. Output/stderr of the LAST segment is returned,
    plus the stderr of intermediate segments (so a failing `grep -q` in a
    chain still shows why).
    """
    started = time.time()
    last_stdout = ""
    stderr_chunks: List[str] = []
    returncode: Optional[int] = None
    timed_out = False
    deadline = started + max(1.0, float(timeout))
    procs: List[subprocess.Popen] = []
    try:
        index = 0
        while index < len(parsed.segments):
            # collect the pipe run starting at `index`
            run_start = index
            while index < len(parsed.segments) - 1 and \
                    parsed.separators[index] == _PIPE:
                index += 1
            run_end = index
            index += 1

            prev = None
            for pos in range(run_start, run_end + 1):
                argv = parsed.segments[pos]
                is_last = pos == run_end
                # Intermediate stderr goes to DEVNULL unless the command asks
                # for 2>&1: an unread stderr pipe blocks the process once it
                # fills (64 KiB), which would deadlock a long pipe run.
                # Only the LAST segment's stderr is captured for the result.
                stderr_arg = (subprocess.STDOUT if parsed.stderr_to_stdout[pos]
                              else (subprocess.DEVNULL if (parsed.stderr_devnull[pos]
                                                          or not is_last)
                                    else subprocess.PIPE))
                stdout_arg = subprocess.PIPE if not is_last else (
                    subprocess.DEVNULL if parsed.stdout_devnull[pos]
                    else subprocess.PIPE)
                proc = _spawn(argv, prev, stdout_arg, stderr_arg)
                procs.append(proc)
                if prev is not None:
                    prev.close()
                prev = proc.stdout
            tail = procs[-1]
            remaining = max(0.1, deadline - time.time())
            try:
                out, err = tail.communicate(timeout=remaining)
            except subprocess.TimeoutExpired:
                timed_out = True
                from phantom.core.executor import _kill_process_tree
                for p in procs:
                    # tree-kill, not just the direct child: a scanner that
                    # spawned helpers must not leave orphans behind.
                    try:
                        _kill_process_tree(p)
                    except Exception:
                        try:
                            p.kill()
                        except OSError:
                            pass
                try:
                    out, err = tail.communicate(timeout=5)
                except Exception:
                    out, err = "", ""
                last_stdout = out or ""
                stderr_chunks.append(err or "")
                returncode = None
                break
            last_stdout = out or ""
            stderr_chunks.append(err or "")
            returncode = tail.returncode
            # drain intermediate segments so they never block on a full pipe
            for p in procs[:-1]:
                try:
                    p.wait(timeout=1)
                except Exception:
                    pass

            sep = (parsed.separators[run_end]
                   if run_end < len(parsed.separators) else None)
            if sep == _AND and returncode != 0:
                break          # short-circuit: the chain stops here
            if sep == _OR and returncode == 0:
                break
    except OSError as exc:
        return QuietResult(parsed.source, error=f"spawn failed: {exc}",
                           returncode=-1)
    finally:
        for p in procs:
            if p.poll() is None:
                try:
                    from phantom.core.executor import _kill_process_tree
                    _kill_process_tree(p)
                except Exception:
                    try:
                        p.kill()
                    except OSError:
                        pass

    stderr_text = "\n".join(c for c in stderr_chunks if c).strip()
    return QuietResult(parsed.source, stdout=last_stdout, stderr=stderr_text,
                       returncode=returncode, timed_out=timed_out,
                       duration=time.time() - started)
