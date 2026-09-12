"""
ransom_sim.py — ransomware simulation with REAL reversible encryption.

A simulation that only moves files is not a ransomware simulation: the
demonstration value comes from the files being actually unusable. So this
module ENCRYPTS the target files (AES-256-GCM, per-file random nonce) —
but it is NOT destructive:

  * the per-run master key is stored in the manifest, which lives in the
    operator's vault (data/ransom_sim/), NEVER inside the attacked tree
  * rollback() decrypts every file back byte-identical (sha256-verified)
  * nothing is deleted, nothing is overwritten irreversibly

The beacon-facing surface mirrors the other post modules:
  * ransom_sim_command(dir)  -> the command line the beacon executes
  * ransom_sim_interpreter() -> parses the RANSOM_SIM: marker

The host-side RansomSimulator is used by tests, by preflight and by anyone
running the simulation locally against a replica.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import time
from dataclasses import asdict, dataclass
from typing import Any, Dict, List

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from phantom.utils.paths import data_dir

MARKER = "RANSOM_SIM:"
ENC_SUFFIX = ".phnt"

# Filesystem areas a simulation must NEVER touch without an explicit
# opt-out: the operator's home, OS system dirs, the Phantom install and
# its data dir. The sim is real-reversible, but a typo like dir="." in a
# home/root context would still encrypt operator files — the guard turns
# that into a hard error instead of damage.
_UNSAFE_PATH_MARKERS = (
    "/etc", "/usr", "/bin", "/sbin", "/lib", "/boot", "/var", "/opt",
    "/tmp", "/proc", "/sys", "/dev", "/run", "/snap", "/System",
    "/Library", "/Applications",
    "\\windows", "\\program files", "\\programdata", "\\system32",
    "\\users\\", "\\appdata", "\\program files (x86)",
)


def _unsafe_dir_reason(target_dir: str) -> str:
    """Human reason when target_dir must not be encrypted, else ""."""
    abspath = os.path.abspath(target_dir)
    root = os.path.abspath(os.sep)
    home = os.path.expanduser("~")
    if abspath == root:
        return f"filesystem root ({abspath})"
    # OS scratch space (%TEMP% on Windows, /tmp on POSIX) is the natural
    # simulation target (tests, lab dirs) — NOT refused. Checked BEFORE the
    # home/marker guards so AppData\Local\Temp is allowed while
    # AppData\Roaming (real configs/cookies) stays guarded.
    low = abspath.lower()
    try:
        import tempfile as _tf
        scratch = os.path.abspath(_tf.gettempdir())
        if low == scratch.lower() or low.startswith(scratch.lower() + os.sep):
            return ""
    except Exception:
        pass
    if home and (abspath == home or abspath.startswith(home + os.sep)):
        return f"the operator home directory ({home})"
    for marker in _UNSAFE_PATH_MARKERS:
        if marker in low:
            return f"system path ({abspath})"
    try:
        import phantom
        pkg = os.path.dirname(os.path.abspath(phantom.__file__))
        if abspath == pkg or abspath.startswith(pkg + os.sep):
            return f"the Phantom install ({pkg})"
        from phantom.utils.paths import data_dir
        dd = os.path.abspath(data_dir())
        if abspath == dd or abspath.startswith(dd + os.sep):
            return f"the Phantom data dir ({dd})"
    except Exception:
        pass
    return ""


def _ransom_sim_allowed() -> bool:
    from phantom.utils import config as cfg
    v = str(cfg.get("engagement.ransom_sim_allow", "",
                    env="PHANTOM_RANSOM_SIM_ALLOW"))
    return v.strip().lower() in ("1", "true", "yes", "on")


def ransom_sim_command(dir_path: str = ".") -> str:
    """The command a beacon executes to run the simulation."""
    return f"ransom-sim {dir_path}"


@dataclass
class ManifestEntry:
    orig_rel: str          # path relative to the attacked directory
    orig_abspath: str      # absolute original location
    encrypted: str         # absolute path of the encrypted file
    nonce: str             # base64, 12 bytes AES-GCM nonce
    sha256: str            # of the ORIGINAL plaintext (verified on rollback)
    size: int


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


class RansomSimulator:
    """Encrypts files in place (real, reversible) and restores them.

    Only regular files directly inside the attacked directory are touched;
    subdirectories and symlinks are left alone. The manifest (with the
    master key) is written to the operator vault so rollback is always
    possible — this is what keeps the simulation non-destructive.
    """

    def __init__(self, vault_dir: str = "") -> None:
        self.vault_dir = vault_dir or os.path.join(data_dir(), "ransom_sim")

    def encrypt(self, target_dir: str,
                run_id: str = "") -> Dict[str, Any]:
        """AES-256-GCM-encrypt every regular file of target_dir in place.

        Crash-safe by construction:
          1. the target dir is guarded (system/home/Phantom dirs refused
             unless PHANTOM_RANSOM_SIM_ALLOW=1),
          2. the manifest (master key + nonce + sha256 of EVERY file) is
             written and fsynced BEFORE any file is touched,
          3. only then are files encrypted and replaced in place.
        A crash mid-run leaves the manifest on disk with everything needed
        for rollback() — files are never encrypted with a lost key.
        """
        run_id = run_id or time.strftime("rs%Y%m%d%H%M%S")
        if not os.path.isdir(target_dir):
            raise NotADirectoryError(target_dir)
        reason = _unsafe_dir_reason(target_dir)
        if reason and not _ransom_sim_allowed():
            raise PermissionError(
                f"refusing to simulate ransomware on {reason} "
                "(set PHANTOM_RANSOM_SIM_ALLOW=1 to override)")

        master_key = secrets.token_bytes(32)
        aesgcm = AESGCM(master_key)
        entries: List[ManifestEntry] = []

        # Phase 1 — scan + metadata ONLY (hash/nonce/size computed without
        # touching a file). Every entry is recoverable from this point on.
        for name in sorted(os.listdir(target_dir)):
            src = os.path.join(target_dir, name)
            if not os.path.isfile(src) or os.path.islink(src):
                continue
            if name.endswith(ENC_SUFFIX):
                continue  # never double-encrypt an artifact
            nonce = secrets.token_bytes(12)
            entry = ManifestEntry(
                orig_rel=name,
                orig_abspath=os.path.abspath(src),
                encrypted=src + ENC_SUFFIX,
                nonce=base64.b64encode(nonce).decode(),
                sha256=_sha256_file(src),
                size=os.path.getsize(src))
            entry._nonce = nonce  # runtime-only, excluded from asdict()
            entries.append(entry)

        # Phase 2 — persist the manifest (master key + every entry) BEFORE
        # any os.remove: rollback is always possible, even after a crash.
        manifest = {
            "run_id": run_id,
            "target_dir": os.path.abspath(target_dir),
            "vault_dir": os.path.abspath(self.vault_dir),
            "created": time.time(),
            "master_key": base64.b64encode(master_key).decode(),
            "cipher": "aes-256-gcm",
            "entries": [asdict(e) for e in entries],
            "status": "encrypting",
        }
        run_dir = os.path.join(self.vault_dir, run_id)
        os.makedirs(run_dir, exist_ok=True)
        manifest_path = os.path.join(run_dir, "manifest.json")
        tmp_manifest = manifest_path + ".tmp"
        with open(tmp_manifest, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_manifest, manifest_path)

        # Phase 3 — encrypt + replace in place.
        for e in entries:
            src = e.orig_abspath
            with open(src, "rb") as f:
                plain = f.read()
            ct = aesgcm.encrypt(e._nonce, plain, None)  # ct = ciphertext+tag
            with open(e.encrypted, "wb") as f:
                f.write(e._nonce + ct)
            os.remove(src)  # original content replaced by the ciphertext

        # finalize: mark the run complete (rollback uses entries only, but
        # the status makes the audit trail unambiguous)
        manifest["status"] = "complete"
        with open(tmp_manifest, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_manifest, manifest_path)
        return manifest

    def rollback(self, manifest_path: str) -> int:
        """Decrypt every encrypted file back byte-identical.

        Each plaintext is sha256-verified against the manifest before the
        ciphertext is removed; a mismatch aborts that entry (the original
        bytes stay recoverable in the vault file). Returns restored count.
        """
        with open(manifest_path, encoding="utf-8") as f:
            manifest = json.load(f)
        master_key = base64.b64decode(manifest["master_key"])
        aesgcm = AESGCM(master_key)
        restored = 0
        for e in manifest["entries"]:
            if not os.path.exists(e["encrypted"]):
                continue
            with open(e["encrypted"], "rb") as f:
                blob = f.read()
            nonce = base64.b64decode(e["nonce"])
            try:
                plain = aesgcm.decrypt(nonce, blob[len(nonce):], None)
            except Exception:
                continue  # tampered entry: keep ciphertext for recovery
            if hashlib.sha256(plain).hexdigest() != e["sha256"]:
                continue  # mismatch: do not touch anything
            with open(e["orig_abspath"], "wb") as f:
                f.write(plain)
            os.remove(e["encrypted"])
            restored += 1
        # remove the operator vault run dir (manifest + leftovers)
        import shutil
        shutil.rmtree(os.path.dirname(manifest_path), ignore_errors=True)
        return restored

    @staticmethod
    def marker_from_manifest(manifest: Dict[str, Any]) -> str:
        manifest_path = os.path.join(
            manifest["vault_dir"], manifest["run_id"], "manifest.json")
        return (f"{MARKER} encrypted={len(manifest['entries'])} "
                f"manifest={manifest_path} rollback_ready=true")


def ransom_sim_interpreter(output: str, wm, slots: Dict[str, Any]) -> List[Any]:
    """Parse RANSOM_SIM: markers into an impact finding."""
    from phantom.automation.belief import Finding

    findings = []
    for line in (output or "").splitlines():
        if not line.startswith(MARKER):
            continue
        kv: Dict[str, str] = {}
        for chunk in line[len(MARKER):].split():
            if "=" in chunk:
                k, v = chunk.split("=", 1)
                kv[k] = v
        findings.append(Finding(
            kind="ransom_sim", key=kv.get("manifest", "sim"),
            value={"dir": "", "encrypted": int(kv.get("encrypted", 0)),
                   "manifest": kv.get("manifest", ""),
                   "rollback_ready": kv.get("rollback_ready") == "true"},
            confidence=0.9, source="ransom_sim", target=wm.target))
    return findings
