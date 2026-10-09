"""
automode_policy.py — range/scope policy for the auto-mode entry point.

The `auto` command used to inline three policy decisions in its
orchestrator: how raw target tokens become targets (CIDR expansion, scope
filtering), what a network range is allowed to authorize (discovery, not
assault) and whether a beacon-bound goal can even call back. The policy
lives here so it is decided (and tested) in ONE place; automode.py only
announces and orchestrates.

Invariant: a range is NOT intent. A CIDR/range token authorizes host
discovery + ranking only; engaging hosts with full chains needs explicit
per-host tokens or the force flag. Identity targets are the engagement
SUBJECT and are never filtered by the machine scope list.
"""

from __future__ import annotations

import ipaddress
from typing import List, Optional

from rich.console import Console

from phantom.utils.notifier import notifier

console = Console()

# Bound on CIDR expansion: a /8 input must never allocate 16M strings in
# RAM just to truncate them to the first 256. Never build the full list.
MAX_CIDR_HOSTS = 256


def extract_networks(raw_targets: List[str]) -> List[str]:
    """CIDR/subnet tokens in the raw target list (e.g. 10.0.0.0/24)."""
    nets = []
    for raw in raw_targets or []:
        for token in raw.split(","):
            token = token.strip()
            if "/" in token:
                try:
                    ipaddress.ip_network(token, strict=False)
                    nets.append(token)
                except ValueError:
                    continue
    return nets


def expand_targets(raw_targets: List[str],
                   scope_list: Optional[List[str]] = None) -> List[str]:
    """Expand CIDR ranges and comma lists into a deduped target list,
    filtered by the engagement scope when provided."""
    from phantom.core.scope import is_in_scope
    out: List[str] = []
    seen = set()

    def _add(t: str) -> None:
        if not t or t in seen:
            return
        if scope_list:
            # identity targets (email/username/phone) are the engagement
            # SUBJECT and are always in scope — the scope list gates the
            # machines (ip/domain/url), not the person being assessed
            from phantom.automation.guidance.targets import (
                classify_target,
                is_identity_target,
            )
            ttype = classify_target(t)
            if not is_identity_target(ttype) and not is_in_scope(t, scope_list):
                notifier.warn(f"{t} fuori scope, ignorato")
                return
        seen.add(t)
        out.append(t)

    for raw in raw_targets:
        for token in raw.split(","):
            token = token.strip()
            if not token:
                continue
            if "/" in token:
                try:
                    net = ipaddress.ip_network(token, strict=False)
                except ValueError:
                    _add(token)  # e.g. a URL path, not a CIDR
                    continue
                # Bound the iteration BEFORE materializing: a /8 input would
                # otherwise allocate 16M strings in RAM just to truncate
                # them to the first 256. Never build the full host list.
                hosts = []
                for i, h in enumerate(net.hosts()):
                    if i >= MAX_CIDR_HOSTS:
                        break
                    hosts.append(str(h))
                if not hosts:
                    hosts = [str(net.network_address)]
                if net.num_addresses > MAX_CIDR_HOSTS:
                    notifier.warn(
                        f"{token}: {net.num_addresses} host, espansione "
                        f"limitata a {MAX_CIDR_HOSTS}")
                for h in hosts:
                    _add(str(h))
            else:
                _add(token)
    return out


# ---------------------------------------------------------------------------
# RANGE POLICY: what a network token authorizes
# ---------------------------------------------------------------------------

def range_policy_verdict(networks: List[str], resolved: List[str],
                         raw: List[str], force_network: bool,
                         plan: bool) -> str:
    """Pure decision: what a range input is allowed to do.

    Returns one of:
      * "engage"          — run the full chain on `resolved`
      * "discovery_only"  — stop after host discovery + ranking
    """
    if networks and not force_network and not plan:
        if len(resolved) > 1 or any("/" in t for t in raw):
            # Dry-run (--plan) always passes: it executes nothing.
            return "discovery_only"
    return "engage"


def apply_range_policy(networks: List[str], resolved: List[str],
                       raw: List[str], force_network: bool,
                       plan: bool) -> bool:
    """Announce + enforce the range policy. Returns True when the run may
    engage `resolved`, False when it must stop (discovery already done)."""
    verdict = range_policy_verdict(networks, resolved, raw,
                                   force_network, plan)
    if verdict == "discovery_only":
        notifier.info("Network scope: discovery-only di default "
                      "(host vivi + ranking, nessun engagement).")
        for t in resolved[:20]:
            console.print(f"  [cyan]{t}[/]")
        if len(resolved) > 20:
            console.print(f"  [dim]... +{len(resolved) - 20} altri "
                          f"(vedi network map)[/]")
        notifier.info("Per ingaggiare: riesegui con host espliciti "
                      "oppure --force-network (full engagement, loud).")
        return False
    if networks and force_network:
        notifier.warn(
            f"FORCE-NETWORK attivo: engagement completo su {len(resolved)} "
            f"host ({', '.join(resolved[:5])}"
            f"{', ...' if len(resolved) > 5 else ''}). Scansioni, exploit "
            f"e brute force gireranno su tutta la rete.")
    return True


def triage_targets(raw: List[str], networks: List[str],
                   resolved: List[str]) -> List[str]:
    """Senior network triage: a CIDR/subnet input gets host discovery +
    surface ranking BEFORE the assault, so the agent pool works the
    richest hosts first instead of spraying full chains on random IPs.

    The discovered + ranked hosts REPLACE the CIDR expansion; only the
    operator's explicit per-host tokens survive the swap (operator intent
    first, then discovered hosts ranked by attack surface). This avoids the
    trap where the 256-host expansion already contains the discovered IPs,
    which would silently keep the whole range.

    Discovery only runs when a network token was actually given; identity
    targets are never triaged. Returns the (possibly unchanged) pool.
    """
    if not networks:
        return resolved
    # ONE engine: discovery + enrichment + exposure ranking all live in
    # netmap (the same code the `map` command and Electron use), so the
    # assault pool and the network map always see the same truth.
    from phantom.core.netmap import triage_networks
    notifier.info(
        f"Network triage: host discovery su {', '.join(networks)}...")
    tri = triage_networks(networks)
    ranked = [r["ip"] for r in tri.get("ranked", [])]
    if not ranked:
        notifier.warn(
            "Nessun host esposto rilevato o nmap assente: espansione "
            "CIDR classica (host a caso nella rete)")
        return resolved
    alive_n = len(tri.get("hosts", []))
    notifier.success(
        f"Host discovery: {alive_n} vivi, ordinati per "
        f"superficie d'attacco (top: {', '.join(ranked[:5])})")
    explicit = [
        t.strip()
        for tok in raw for t in tok.split(",")
        if t.strip() and "/" not in t
        and t.strip() not in networks
    ]
    seen = set(explicit)
    ranked = [h for h in ranked
              if not (h in seen or seen.add(h))]
    return explicit + ranked


def warn_missing_scope(resolved: List[str]) -> None:
    """Fail-loud when network targets run without an engagement scope.

    A-6: auto-mode FAILS CLOSED without a scope (the agent gate refuses
    unless the operator explicitly opted out), so this is no longer a
    silent warn-and-continue — but the operator is told WHY up front.
    """
    try:
        from phantom.automation.guidance.targets import (
            classify_target,
            is_identity_target,
        )
        net_targets = [t for t in resolved
                       if not is_identity_target(classify_target(t))]
    except Exception:
        net_targets = list(resolved)
    if net_targets:
        notifier.warn(
            "NESSUNO SCOPE impostato su target di rete: l'auto-mode "
            "rifiuterà i target finché non imposti 'set scope "
            "<cidr,...>' (o scope_list). Per un lab dichiara "
            "l'eccezione con PHANTOM_ALLOW_UNSCOPED=1 — un typo nel "
            "target o un CIDR largo colpiscono davvero.")


def callback_preflight(targets, goal: str, notifier=notifier) -> None:
    """Say it BEFORE the run when a beacon-bound goal cannot call back.

    The beacon's endpoint is compiled from `c2.host`. When the target
    cannot dial it (unset host, 0.0.0.0, loopback, or a private endpoint
    against an external target) the deploy SUCCEEDS and the beacon never
    checks in — the operator then reads a late "nessun beacon stabilito"
    with no cause. This is the most common real-deploy failure, so it is
    named up front (warn when some targets are affected, error when none
    can work). Never blocks the run: a tunnel may exist that we cannot
    see from here.

    `notifier` is injectable so the orchestrator can hand in its own
    announcer (tests replace automode.notifier wholesale).
    """
    if goal not in ("beacon", "deliver", "complete_kill_chain",
                    "post_exploit", "deep"):
        return
    # Materialise ONCE. This function walks `targets` and then compares
    # len(bad) against len(targets): given a generator the first walk exhausts
    # it, the second walk yields nothing, and the "no target can call back"
    # error - the one that saves a wasted deploy - could never fire. Today's
    # callers pass lists, which is exactly why this stayed latent.
    try:
        targets = list(targets)
    except TypeError:
        return
    try:
        from phantom.utils import config as cfg
        from phantom.utils.network import callback_plausibility, get_c2_endpoint
        advertised = cfg.get_str("c2.host", "") or get_c2_endpoint()[0]
    except Exception:
        return
    bad = []
    for t in targets:
        try:
            ok, reason = callback_plausibility(t, advertised)
        except Exception:
            continue
        if not ok:
            bad.append((t, reason))
    for t, reason in bad:
        notifier.warn(f"Callback implausibile per {t}: {reason}")
    if bad and len(bad) == len(list(targets)):
        notifier.error(
            "Nessun target può chiamare il C2: i beacon si deployerebbero "
            "ma non rientrerebbero MAI.",
            hint="imposta c2.host all'indirizzo operatore raggiungibile dal "
                 "target (o fai port-forward) — `doctor --net` verifica il "
                 "listener")
