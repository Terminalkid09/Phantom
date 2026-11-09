"""audit_log.py — HMAC-authenticated, hash-chained audit log.

Every C2 security-relevant event (beacon registration, task queueing,
task results, auth failures, operator logins) is appended to a JSONL
file where each record carries:

  * seq   — monotonic sequence number
  * prev  — the hash of the previous record (genesis: 64 zeros)
  * hash  — SHA-256 over the canonical JSON of the record WITHOUT `hash`
  * hmac  — HMAC-SHA256 over the canonical record WITHOUT `hmac`

The HMAC key lives in a separate owner-only file (or is supplied
explicitly).  A hash chain alone proves *internal consistency*, not
authenticity: an attacker who can edit the JSONL can recompute every hash.
The HMAC makes the chain unforgeable without the key.

The signed head file (`<log>.head`) binds the latest seq/hash, so deleting
the tail of the log is detected too.  The head and the key are created next
to the log; both are held to the same owner-only permissions as the log.

Existing hash-only logs are sealed once, on first append/verify: the current
records receive their HMAC and a signed head is written.  The historical
coverage is therefore exactly what existed at migration time; after that,
every append is authenticated.

Design notes:
  * append-only: records are never updated or deleted in place after sealing
  * file lock: a threading.Lock guards concurrent appends; a sidecar lock
    file makes the whole read-compute-write section safe across processes
  * bounded read cost: `verify()` streams the file once
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import random
import secrets
import tempfile
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

_GENESIS = "0" * 64
_KEY_SUFFIX = ".key"
_HEAD_SUFFIX = ".head"


def _canonical(record: Dict[str, Any]) -> str:
    """Stable JSON serialization used for hashing (sorted keys, no spaces)."""
    return json.dumps(record, sort_keys=True, separators=(",", ":"),
                      default=str)


def _body(record: Dict[str, Any]) -> Dict[str, Any]:
    """Record fields covered by the chain hash (not the MAC itself)."""
    return {k: v for k, v in record.items() if k not in ("hash", "hmac")}


def _mac_body(record: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in record.items() if k != "hmac"}


class AuditLog:
    """Append-only, HMAC-authenticated, hash-chained JSONL audit log."""

    def __init__(self, path: Optional[str] = None,
                 key: Optional[bytes | str] = None) -> None:
        if path is None:
            from phantom.utils.paths import data_dir
            path = os.path.join(data_dir(), "c2_audit.log")
        self.path = path
        self._explicit_key = (key.encode("utf-8") if isinstance(key, str)
                              else key)
        self._key: Optional[bytes] = self._explicit_key
        self._key_path = ""
        self._lock = threading.Lock()

    # --------------------------------------------------------------- key/head
    def _key_file(self) -> str:
        return self.path + _KEY_SUFFIX

    def _head_file(self) -> str:
        return self.path + _HEAD_SUFFIX

    def _load_key_locked(self) -> bytes:
        """Load or create the HMAC key under the cross-process lock."""
        key_path = self._key_file()
        if self._explicit_key is not None:
            self._key = self._explicit_key
            self._key_path = key_path
            return self._key
        if self._key is not None and self._key_path == key_path:
            return self._key
        try:
            with open(key_path, "r", encoding="utf-8") as f:
                raw = f.read().strip()
            if not raw:
                raise ValueError("empty audit key")
            try:
                key = bytes.fromhex(raw)
            except ValueError:
                key = raw.encode("utf-8")
        except FileNotFoundError:
            key = secrets.token_bytes(32)
            directory = os.path.dirname(key_path) or "."
            os.makedirs(directory, exist_ok=True)
            fd, temp_path = tempfile.mkstemp(
                prefix=".phantom-audit-key-", dir=directory)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    f.write(key.hex() + "\n")
                    f.flush()
                    os.fsync(f.fileno())
                from phantom.utils.secret_store import harden_file
                harden_file(temp_path, 0o600)
                os.replace(temp_path, key_path)
                harden_file(key_path, 0o600)
            finally:
                try:
                    os.unlink(temp_path)
                except FileNotFoundError:
                    pass
        self._key = key
        self._key_path = key_path
        return key

    def _record_mac(self, record: Dict[str, Any]) -> str:
        assert self._key is not None
        return hmac.new(self._key, _canonical(_mac_body(record)).encode("utf-8"),
                        hashlib.sha256).hexdigest()

    def _head_mac(self, seq: int, digest: str) -> str:
        assert self._key is not None
        body = {"seq": seq, "hash": digest}
        return hmac.new(self._key, _canonical(body).encode("utf-8"),
                        hashlib.sha256).hexdigest()

    def _write_head_locked(self, record: Dict[str, Any]) -> None:
        """Persist the signed head after a record is durable.

        The head is tiny and rewritten on every append, so this is a direct
        truncate-and-write rather than the atomic-temp path: on Windows the
        latter ran ``icacls`` twice per append, and 80 concurrent appends
        spent long enough under the file lock to hit the lock timeout. A
        crash mid-write leaves a corrupt head, which verify() reports as
        tampering; the next append rewrites it. Never fail open.
        """
        head = {
            "seq": record.get("seq"),
            "hash": record.get("hash"),
            "hmac": self._head_mac(int(record.get("seq") or 0),
                                   str(record.get("hash") or "")),
        }
        path = self._head_file()
        existed = os.path.exists(path)
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, (_canonical(head) + "\n").encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
        if not existed:
            from phantom.utils.secret_store import harden_file
            harden_file(path, 0o600)

    def _verify_head_locked(self, last: Optional[Dict[str, Any]]
                            ) -> Tuple[bool, Optional[Dict[str, Any]]]:
        head_path = self._head_file()
        if not os.path.isfile(head_path):
            if last is None:
                return True, None
            return False, {"_head": "missing"}
        try:
            with open(head_path, "r", encoding="utf-8") as f:
                head = json.load(f)
            seq = int(head.get("seq"))
            digest = str(head.get("hash") or "")
            stored = str(head.get("hmac") or "")
        except (OSError, ValueError, TypeError):
            return False, {"_head": "corrupt"}
        if last is None:
            return False, {"_head": "log missing"}
        if not hmac.compare_digest(stored, self._head_mac(seq, digest)):
            return False, {"_head": "bad hmac"}
        if seq != last.get("seq") or digest != last.get("hash"):
            return False, {"_head": "does not match tail"}
        return True, None

    def _write_text_atomic(self, path: str, text: str) -> None:
        directory = os.path.dirname(path) or "."
        os.makedirs(directory, exist_ok=True)
        fd, temp_path = tempfile.mkstemp(
            prefix=".phantom-audit-", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
                f.write(text)
                f.flush()
                os.fsync(f.fileno())
            from phantom.utils.secret_store import harden_file
            harden_file(temp_path, 0o600)
            os.replace(temp_path, path)
            harden_file(path, 0o600)
        finally:
            try:
                os.unlink(temp_path)
            except FileNotFoundError:
                pass

    def _locked_fd(self):
        """Cross-process exclusive lock on a sidecar .lock file.

        The C2 listener, the shell and agent workers share the log inside
        one process (threading.Lock covers that) but a second Phantom
        process (second operator shell, Electron backend + CLI at once)
        must not interleave records — the chain-of-custody log has to stay
        line-atomic. Returns an unlock callable.
        """
        lock_path = self.path + ".lock"
        os.makedirs(os.path.dirname(lock_path) or ".", exist_ok=True)
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        if os.name == "nt":
            import errno
            import msvcrt
            # Windows locks a byte RANGE, so the file must have one byte.
            if os.fstat(fd).st_size == 0:
                os.write(fd, b"\0")
            os.lseek(fd, 0, os.SEEK_SET)
            # LK_LOCK gives up after ~10 s under heavy contention (measured
            # in the two-process append test: 80 appends, each hardening a
            # file with icacls). A bounded retry on the non-blocking lock is
            # both fairer and does not turn contention into EDEADLOCK.
            deadline = time.monotonic() + 30.0
            while True:
                try:
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                    break
                except OSError as exc:
                    if (time.monotonic() >= deadline
                            or exc.errno not in (errno.EACCES,
                                                 errno.EDEADLK,
                                                 errno.EAGAIN)):
                        os.close(fd)
                        raise
                    time.sleep(0.005 + random.random() * 0.015)

            def _unlock():
                try:
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                finally:
                    os.close(fd)
        else:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_EX)

            def _unlock():
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                finally:
                    os.close(fd)
        return _unlock

    def _write_line(self, line: str) -> None:
        """Append one full line (O_APPEND + fsync). Caller holds the
        cross-process lock, so the write is line-atomic and durable."""
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND,
                     0o600)
        try:
            os.write(fd, line.encode("utf-8") + b"\n")
            os.fsync(fd)
        finally:
            os.close(fd)

    # ------------------------------------------------------------------ append

    def append(self, event: str, **fields: Any) -> Dict[str, Any]:
        """Append one event; returns the record as written.

        Every field is REDACTED before hashing/writing: the audit log is the
        chain-of-custody record that can be shown to the client, so raw
        passwords/OTPs/tokens must never land in it (a `command` field like
        "sshpass -p secret ssh ..." would otherwise leak the credential).
        The hash and HMAC cover the redacted record, so the chain stays
        verifiable.
        """
        from phantom.utils.redact import redact as _redact_obj
        from phantom.utils.redact import redact_text as _redact_text
        with self._lock:
            # The WHOLE read-compute-write is one critical section across
            # BOTH the thread lock and the cross-process file lock: two
            # processes must not both read the same tail (same prev/seq)
            # before either writes, or the hash chain forks.
            unlock = self._locked_fd()
            try:
                self._load_key_locked()
                self._seal_legacy_locked()
                prev = self._last_hash()
                record: Dict[str, Any] = {
                    "seq": self._count() + 1,
                    "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "event": event,
                }
                record.update(fields)
                # KEY-based redaction first (a field literally named
                # `password`/`otp` is masked whatever its value), then
                # TEXT-based masking for string values (a `command` field
                # carrying "sshpass -p secret ..." is masked in place).
                record = _redact_obj(record)
                record = {k: (_redact_text(v) if isinstance(v, str) else v)
                          for k, v in record.items()}
                record["prev"] = prev
                record["hash"] = hashlib.sha256(
                    _canonical(_body(record)).encode("utf-8")).hexdigest()
                record["hmac"] = self._record_mac(record)
                self._write_line(_canonical(record))
                self._write_head_locked(record)
            finally:
                unlock()
            return record

    # ------------------------------------------------------------------ reads

    def _iter(self):
        if not os.path.isfile(self.path):
            return
        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except ValueError:
                    yield {"_corrupt": line}

    def _count(self) -> int:
        n = 0
        for _ in self._iter():
            n += 1
        return n

    def _last_hash(self) -> str:
        last = _GENESIS
        for rec in self._iter():
            if isinstance(rec, dict) and rec.get("hash"):
                last = rec["hash"]
        return last

    def tail(self, n: int = 20) -> List[Dict[str, Any]]:
        """Last `n` records (oldest first)."""
        records = [r for r in self._iter()]
        return records[-n:]

    def _seal_legacy_locked(self) -> bool:
        """Give old hash-only records their HMAC and write the signed head.

        The migration preserves seq/prev/hash exactly; the HMAC covers the
        existing bytes, so it authenticates the log as it stood when this
        build first touched it. It is safe to repeat (once every record has
        an hmac this is a no-op).
        """
        if not os.path.isfile(self.path):
            return False
        records = list(self._iter())
        if not records or any("_corrupt" in r for r in records):
            return False
        if all(isinstance(r, dict) and r.get("hmac") for r in records):
            return False
        for rec in records:
            rec["hmac"] = self._record_mac(rec)
        text = "\n".join(_canonical(rec) for rec in records) + "\n"
        self._write_text_atomic(self.path, text)
        self._write_head_locked(records[-1])
        return True

    # ----------------------------------------------------------------- verify

    def verify(self) -> Tuple[bool, int, Optional[Dict[str, Any]]]:
        """Verify the HMAC, the hash chain and the signed head.

        Returns (ok, records_checked, first_bad_record_or_None).
        """
        with self._lock:
            unlock = self._locked_fd()
            try:
                self._load_key_locked()
                self._seal_legacy_locked()
                prev = _GENESIS
                seq = 0
                last: Optional[Dict[str, Any]] = None
                for rec in self._iter():
                    seq += 1
                    last = rec
                    if "_corrupt" in rec:
                        return False, seq, rec
                    stored_hash = rec.get("hash", "")
                    expect = hashlib.sha256(
                        _canonical(_body(rec)).encode("utf-8")).hexdigest()
                    if rec.get("prev") != prev or stored_hash != expect:
                        return False, seq, rec
                    stored_mac = str(rec.get("hmac") or "")
                    if not hmac.compare_digest(
                            stored_mac, self._record_mac(rec)):
                        return False, seq, rec
                    prev = stored_hash
                    if rec.get("seq") != seq:
                        return False, seq, rec
                ok, bad = self._verify_head_locked(last)
                if not ok:
                    return False, seq, bad
                return True, seq, None
            finally:
                unlock()


audit_log = AuditLog()
