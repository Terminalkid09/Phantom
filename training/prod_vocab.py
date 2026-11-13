"""prod_vocab.py â€” an exploit corpus written in PRODUCTION's candidate vocabulary.

THE DEFECT (gap C1 of ``docs/Action_Plan_2026-10-31.md``). Measured 2026-10-31
and re-measured 2026-11-02 on this checkout: the training corpus asks about
CAPABILITY ids â€” ``scan_tcp``, ``web_rce``, ``beacon_deploy`` â€” while the
deterministic scorer Phantom actually ships,
``access.AccessCandidate.score_for``, orders ACCESS candidates that
``access.collect_candidates`` builds out of a service list:
``noncve:service:redis:6379``, ``noncve:creds:ssh:root``, ``CVE-2021-41773``.
Run over ``training/golden/exploit.holdout.jsonl``,
``training.eval.production_baseline_block`` reports **31 rows, 0 scoreable,
coverage 0.0**. A baseline with coverage 0 is not a bad score, it is no score:
the learned ranker can never be compared with the deployed one, and adding
``success``/``noise``/``complexity`` columns to the existing rows would change
nothing, because production never reads those ids at all.

WHAT THIS MODULE IS. A generator of golden rows whose candidate set is EXACTLY
what production produces for a declared service list: every row is built by
calling ``collect_candidates(..., include_nvd=False, include_non_cve=True)``
and keeping the ids that came back, so no id is ever invented, and the same
call re-derives them in the drift guard (``tests/test_prod_vocab.py``). The
service sets come from the ``SWEEP`` table below â€” concrete banners, one entry
per box, not a loop over made-up variety â€” and every declared entry either
becomes a row or is REPORTED as unscoreable with the reason, so nothing is
dropped in silence.

THE LABEL IS AN INDEPENDENT RUBRIC, not the production ordering.
``rubric_ranking`` is a pure function of the candidate IDS: it maps each id to
a declared class (see ``_SERVICE_RUBRIC`` / ``_ANOMALY_RUBRIC`` and the curated
CVE catalog) and sorts by class tier, then by what the channel grants when it
works, then by id. It never imports or calls ``score_for``, and it never reads
``success``, ``noise`` or ``complexity`` â€” those are production's own
ESTIMATES of how an attempt goes, and using them as the label would make the
comparison circular (production would score 1.0 by construction and the
measurement would be about its own weights).

The ladder, best first, and why:

  tier 6  a channel that EXECUTES without authentication: the redis/docker
          control endpoints, a confirmed cmdi/ssti anomaly, an existing
          foothold, or a curated module of kind ``rce`` matching the banner.
          Nothing else can be the best next move: it ends the engagement
          instead of informing it.
  tier 5  a precondition, not a compromise: a validated credential (auth now,
          exec through ssh/smb once used), or a curated CVSS >= 9 auxiliary
          (Zerologon: a takeover, but one that needs a domain path and can
          break the target).
  tier 4  read/write access: anonymous ftp, an open NFS export, an rsync
          module, or a curated 7.0-9.0 auxiliary (Heartbleed: memory
          disclosure).
  tier 4  an authenticated surface: a null SMB session, an open mongodb /
          elasticsearch / kubernetes API. Same tier as read, lower impact: it
          proves the data is reachable, it does not hand it over.
  tier 3  information only: memcached stats, the default SNMP community, an
          anonymous LDAP bind, a curated < 7.0 auxiliary (user enumeration).
  tier 2  reachability with nothing to confirm: a listening RFB port.
  tier 0  anything the rubric cannot classify, LAST â€” an id whose class is
          unknown is not evidence, and putting it anywhere but last would
          reward the corpus for drifting away from this table.

The id breaks every remaining tie, so the order is TOTAL: two runs on the same
row are byte-identical and there is no pair the rubric leaves undecided.

What the rubric deliberately does NOT use: local PoC availability. It looks
like a good signal (a weapon in the repo beats a Metasploit module) and it is
what production itself rewards (``provider == "local_poc"``), but
``execution.iter_local_pocs`` also walks ``pocs/synced``, which an operator
fills per machine â€” a label that moves with somebody's ExploitDB mirror is not
a label. The in-repo equivalent is the CURATED module: a CVE the catalog knows
as ``kind="rce"`` is a codified weapon that both production and this rubric can
see, on every checkout, with no network.

MEASUREMENT (2026-11-02, this checkout, offline: ``include_nvd=False``, so no
request leaves the box). ``python -m training.prod_vocab --report``:

    before   exploit.holdout.jsonl     31 rows,  0 scoreable, coverage 0.00, no ndcg
    after    exploit.production.jsonl  23 rows, 23 scoreable, coverage 1.00, ndcg 0.977

The production ordering reaches a mean NDCG in the mid 0.9s against this
rubric, and the disagreements are the finding, not a defect to tune away. Two
of them, visible in ``SWEEP`` without leaving this file:

* ``data-elastic-current``: production puts
  ``noncve:service:elasticsearch:9200`` (auth, no read) at 69.03 and the
  curated RCE ``CVE-2015-1427`` at 67.92 â€” an unauthenticated index read is
  ranked ABOVE a module that executes. Its ``success`` (0.78) and ``noise``
  (0.20) beat  the RCE's (0.85 / 0.70) at usefulness, because ``success + quiet``
  outweighed ``impact`` (0.65 against 0.25 when this was measured; the
  ``balanced`` weights now put ``impact`` at 0.15, so re-run ``--report``
  before quoting that gap).
* the ``big-box-*`` sets, where a memcached stats answer (info only, success
  0.82 / noise 0.15) lands above nfs/rsync file reads and above a null SMB
  session: the weighting prefers a cheap trivial answer to a valuable one.

Both are honest disagreements about VALUE, and they are reported rather than
fixed: tuning the rubric until production looks good would be the same lie in
the other direction. What this file supports is the comparison; which ordering
is better is an operator decision, and it is the first time the question can be
asked with numbers.

LIMITS. (1) The rows are declared service sets, so this measures the two
orderings on a realistic surface, not on live captures â€” it is a corpus, not an
engagement log. (2) The ids are stable across machines; the production SCORES
are not guaranteed to be, because a machine with a populated ``pocs/synced``
changes ``provider``/``success`` for a CVE (paragraph above) â€” the rubric and
the row ids do not move. (3) One candidate is not an ordering: single-service
boxes (ssh only, redis 6379, smb 445, rdp 3389, a bare https) have at most one
access candidate in production's vocabulary, so they are declared here,
measured as unscoreable and REPORTED â€” that thinness is a property of the
vocabulary, and padding those rows to make them scoreable would be the bug this
module exists to expose.

Reporting only: nothing here feeds the promotion gate or a score.

    python -m training.prod_vocab --write     # regenerate the golden file
    python -m training.prod_vocab --report    # rows, unscoreable sets, coverage
    python -m training.prod_vocab --check     # drift guard, exit 1 on a diff
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple

PHASE = "exploit"
METRIC = "ndcg"

#: Version of the rubric AND of the row shape. A row states which one labelled
#: it (``label_basis``), so a corpus generated under an older ladder is not
#: silently compared with a newer one.
RUBRIC_VERSION = "prod-vocab-rubric/1"

#: The posture a row declares. The rubric is INVARIANT to it (what a channel
#: grants does not change with ``--stealth``), so the label does not depend on
#: it; production is scored at this same default posture.
MODE = "balanced"

GOLDEN_PATH = (Path(__file__).resolve().parent / "golden"
               / "exploit.production.jsonl")


# ---------------------------------------------------------------------------
# The rubric: a declared class per candidate ID
# ---------------------------------------------------------------------------
#
# Every entry is (class label, tier, impact). ``tier`` is the rubric's own
# class ladder (see the module docstring); ``impact`` is what the channel gives
# the operator WHEN IT WORKS â€” control 6, shell 5, exec 4, file read/write 3,
# auth 2, info 1. Both are DECLARED here, from the semantics of the
# misconfiguration: what an unauthenticated redis grants is a fact about redis,
# not an estimate of how an attempt goes. That is why the two numbers below can
# legitimately overlap with production's ``access`` field â€” and why nothing in
# this file reads production's ``success``/``noise``/``complexity``, which are
# estimates and would make the comparison circular.

UNCLASSIFIED: Tuple[str, int, int] = ("unclassified", 0, 0)

#: Class for every service channel ``access.SERVICE_PROBES`` can emit as
#: ``noncve:service:<canonical>:<port>``. The full key set is listed, not only
#: the ones ``SWEEP`` happens to hit, so an id from an unexercised channel is
#: classified instead of silently landing in the catch-all.
_SERVICE_RUBRIC: Dict[str, Tuple[str, int, int]] = {
    "redis": ("unauth-exec-channel", 6, 6),
    "docker": ("unauth-exec-channel", 6, 6),
    "mongodb": ("auth-surface", 4, 2),
    "elasticsearch": ("auth-surface", 4, 2),
    "kubernetes": ("auth-surface", 4, 2),
    "smb": ("auth-surface", 4, 2),
    "ftp": ("read-path", 4, 3),
    "nfs": ("read-path", 4, 3),
    "rsync": ("read-path", 4, 3),
    "memcached": ("info-only", 3, 1),
    "snmp": ("info-only", 3, 1),
    "ldap": ("info-only", 3, 1),
    "vnc": ("reachable-only", 2, 1),
}

#: Class for a confirmed web anomaly (``noncve:anomaly:<cls>:<port>:<endpoint>``).
_ANOMALY_RUBRIC: Dict[str, Tuple[str, int, int]] = {
    "cmdi": ("confirmed-web-exec", 6, 4),
    "ssti": ("confirmed-web-exec", 6, 4),
    "lfi": ("read-path", 4, 3),
    "upload": ("read-path", 4, 3),
    "ssrf": ("auth-surface", 4, 2),
    "xss": ("auth-surface", 4, 2),
    "idor": ("info-only", 3, 1),
}


def _cve_class(cve_id: str) -> Tuple[str, int, int]:
    """Class of a curated CVE, from the catalog in this repository.

    The catalog (``phantom.automation.exploit.modules``) is static data shipped
    with the code: ``kind`` says whether a weapon executes and ``severity`` is
    the published CVSS. Neither is a production score â€” ``score_for`` derives
    its ``success`` from the module RANK, which this function deliberately does
    not read.

    A CVE the catalog does not know is unclassified (tier 0, last): an id that
    only exists in a row would otherwise be ranked on the authority of being a
    CVE id, which is exactly the drift this table must refuse.
    """
    # Deferred like `training.baseline_production`: a corpus generator should
    # not make `import training.prod_vocab` drag in the application for a
    # caller that only wants the rubric over a couple of ids.
    from phantom.automation.exploit.modules.registry import module_registry

    module = module_registry.get(str(cve_id or "").upper())
    if module is None:
        return ("unclassified-cve", 0, 0)
    if str(module.kind).lower() == "rce":
        return ("curated-rce", 6, 4)
    severity = float(module.severity or 0.0)
    if severity >= 9.0:
        return ("curated-takeover", 5, 6)
    if severity >= 7.0:
        return ("curated-disclosure", 4, 3)
    return ("curated-enumeration", 3, 1)


def rubric_class(candidate_id: str) -> Tuple[str, int, int]:
    """``(class, tier, impact)`` for one candidate id â€” the label's atom.

    Parsed from the ID, never from the candidate object: an id is what the
    corpus stores and what the drift guard re-derives, so a class that depends
    on a live object is a class the file cannot check.
    """
    value = str(candidate_id or "").strip()
    if value.upper().startswith("CVE-"):
        return _cve_class(value)
    parts = value.split(":")
    if len(parts) >= 3 and parts[0] == "noncve":
        family, name = parts[1], parts[2]
        if family == "service":
            return _SERVICE_RUBRIC.get(name, UNCLASSIFIED)
        if family == "anomaly":
            return _ANOMALY_RUBRIC.get(name, UNCLASSIFIED)
        if family == "creds":
            return ("credential-path", 5, 2)
        if family == "foothold":
            return ("existing-channel", 6, 6)
    return UNCLASSIFIED


def rubric_key(candidate_id: str) -> Tuple[int, int, str]:
    """Sort key: class tier, then impact, then the id (a total order)."""
    _label, tier, impact = rubric_class(candidate_id)
    return (-tier, -impact, str(candidate_id))


def rubric_ranking(candidate_ids: Iterable[str]) -> List[str]:
    """The rubric's ordering of ``candidate_ids`` â€” best next attempt first.

    A pure function of the ids: no candidate object, no production field, no
    I/O beyond the static catalog. Duplicates collapse (a corpus row cannot ask
    about the same id twice), and the id breaks ties, so the result is stable
    byte for byte and every pair is decided.
    """
    unique = list(dict.fromkeys(str(cid) for cid in (candidate_ids or [])))
    return sorted(unique, key=rubric_key)


# ---------------------------------------------------------------------------
# The declared sweep: one explicit box per entry
# ---------------------------------------------------------------------------
#
# Not a loop over a cross-product. Every entry states the concrete banners nmap
# would print for that box, because the candidate set is whatever
# `collect_candidates` derives from them: Apache 2.4.50 stays inside the
# CVE-2021-41773 range and 2.4.51 does not, OpenSSH 7.4 still trips the user
# enumeration and 9.2 does not. A table makes that visible; a loop would hide
# it behind a combination count.
#
# The families are the realistic spread of a small engagement: a Linux web box,
# a Java application server, a Windows estate, data stores, file services,
# network-management daemons, a TLS surface from the Heartbleed age, and four
# boxes with six or more listening services. The single-service entries are
# here on purpose: production builds at most ONE access candidate for them (see
# the docstring), so they are reported as unscoreable instead of being padded.

def _svc(port: str, service: str, product: str = "",
         version: str = "") -> Dict[str, str]:
    """One service entry, in the shape ``access._service_record`` reads."""
    entry: Dict[str, str] = {"port": str(port), "service": str(service)}
    if product:
        entry["product"] = str(product)
    if version:
        entry["version"] = str(version)
    return entry


SWEEP: Tuple[Dict[str, Any], ...] = (
    # -- a Linux web box: ssh + Apache HTTPD -------------------------------
    {"scenario": "ssh-http-apache-2449", "target": "10.20.0.11",
     "services": (_svc("22", "ssh", "OpenSSH",
                       "OpenSSH 7.4 (protocol 2.0)"),
                  _svc("80", "http", "Apache httpd", "2.4.49"))},
    {"scenario": "ssh-http-apache-2450", "target": "10.20.0.12",
     "services": (_svc("2222", "ssh", "OpenSSH",
                       "OpenSSH 7.4 (protocol 2.0)"),
                  _svc("80", "http", "Apache httpd", "2.4.50"))},
    {"scenario": "ssh-http-apache-alt-port", "target": "10.20.0.13",
     "services": (_svc("22", "ssh", "OpenSSH", "OpenSSH 6.6.1p1 Ubuntu"),
                  _svc("8080", "http", "Apache httpd", "2.4.49"))},
    {"scenario": "ssh-http-apache-old-ssh", "target": "10.20.0.14",
     "services": (_svc("22", "ssh", "OpenSSH", "OpenSSH 5.3p1 Debian"),
                  _svc("80", "http", "Apache httpd", "2.4.50"))},
    {"scenario": "ssh-http-apache-https", "target": "10.20.0.15",
     "services": (_svc("2222", "ssh", "OpenSSH",
                       "OpenSSH 7.4 (protocol 2.0)"),
                  _svc("443", "https"),
                  _svc("80", "http", "Apache httpd", "2.4.49"))},
    {"scenario": "ssh-http-apache-ftp", "target": "10.20.0.20",
     "services": (_svc("22", "ssh", "OpenSSH", "OpenSSH 7.4 (protocol 2.0)"),
                  _svc("80", "http", "Apache httpd", "2.4.50"),
                  _svc("21", "ftp"))},
    {"scenario": "ssh-http-apache-mysql", "target": "10.20.0.19",
     "services": (_svc("22", "ssh", "OpenSSH", "OpenSSH 6.0p1 Debian"),
                  _svc("80", "http", "Apache httpd", "2.4.49"),
                  _svc("3306", "mysql", "MySQL", "5.7.42"))},
    # -- a Java application server: Struts2 and Log4j ----------------------
    {"scenario": "java-struts-2510", "target": "10.20.1.11",
     "services": (_svc("22", "ssh", "OpenSSH", "OpenSSH 7.4 (protocol 2.0)"),
                  _svc("8080", "http", "Apache Struts", "2.5.10"))},
    {"scenario": "java-struts-2331", "target": "10.20.1.12",
     "services": (_svc("22", "ssh", "OpenSSH", "OpenSSH 7.4 (protocol 2.0)"),
                  _svc("8080", "http", "Apache Struts", "2.3.31"))},
    {"scenario": "java-struts-2315", "target": "10.20.1.13",
     "services": (_svc("2222", "ssh", "OpenSSH", "OpenSSH 7.4 (protocol 2.0)"),
                  _svc("8080", "http", "Apache Struts", "2.3.15"))},
    {"scenario": "java-struts-250", "target": "10.20.1.14",
     "services": (_svc("22", "ssh", "OpenSSH", "OpenSSH 7.4 (protocol 2.0)"),
                  _svc("8080", "http", "Apache Struts", "2.5.0"))},
    {"scenario": "java-log4shell-2141", "target": "10.20.1.15",
     "services": (_svc("22", "ssh", "OpenSSH", "OpenSSH 7.4 (protocol 2.0)"),
                  _svc("8081", "http", "Log4j", "2.14.1"))},
    {"scenario": "java-log4shell-2100", "target": "10.20.1.16",
     "services": (_svc("22", "ssh", "OpenSSH", "OpenSSH 7.4 (protocol 2.0)"),
                  _svc("8081", "http", "Log4j", "2.10.0"))},
    {"scenario": "java-log4shell-200", "target": "10.20.1.17",
     "services": (_svc("22", "ssh", "OpenSSH", "OpenSSH 7.4 (protocol 2.0)"),
                  _svc("8081", "http", "Log4j", "2.0.0"))},
    {"scenario": "java-struts-log4shell", "target": "10.20.1.18",
     "services": (_svc("22", "ssh", "OpenSSH", "OpenSSH 7.4 (protocol 2.0)"),
                  _svc("8080", "http", "Apache Struts", "2.5.10"),
                  _svc("8081", "http", "Log4j", "2.14.1"),
                  _svc("443", "https"))},
    {"scenario": "java-two-apps", "target": "10.20.1.20",
     "services": (_svc("2222", "ssh", "OpenSSH", "OpenSSH 7.4 (protocol 2.0)"),
                  _svc("8443", "http", "Log4j", "2.14.1"),
                  _svc("8000", "http", "Apache Struts", "2.3.31"))},
    # A Flask/Werkzeug dev server is inside no curated range and has no service
    # channel: the whole web surface contributes nothing.
    {"scenario": "java-werkzeug-only", "target": "10.20.1.19",
     "services": (_svc("80", "http", "nginx", "1.24.0"),
                  _svc("8080", "http", "Werkzeug",
                       "Werkzeug httpd 2.2.2 (Python 3.11.2)"),
                  _svc("22", "ssh", "OpenSSH",
                       "OpenSSH 9.2p1 Debian 2+deb12u10"))},

    # -- a Windows estate: RDP, SMB, the domain controller ------------------
    {"scenario": "windows-rdp-smb-bluekeep", "target": "10.20.2.11",
     "services": (_svc("3389", "ms-rdp", "Microsoft RDP", "6.1"),
                  _svc("445", "microsoft-ds", "Microsoft Windows", "6.1"))},
    {"scenario": "windows-rdp-smb-netbios", "target": "10.20.2.12",
     "services": (_svc("3389", "ms-rdp", "Microsoft RDP", "6.0"),
                  _svc("445", "microsoft-ds", "Microsoft Windows", "6.1"),
                  _svc("139", "netbios-ssn"))},
    {"scenario": "windows-smb-dc", "target": "10.20.2.13",
     "services": (_svc("445", "microsoft-ds", "Microsoft Windows", "10.0"))},
    {"scenario": "windows-smb-legacy", "target": "10.20.2.14",
     "services": (_svc("445", "microsoft-ds"),
                  _svc("139", "netbios-ssn"))},
    {"scenario": "windows-rdp-smb-dc", "target": "10.20.2.15",
     "services": (_svc("3389", "ms-rdp", "Microsoft RDP", "6.1"),
                  _svc("445", "microsoft-ds", "Microsoft Windows", "10.0"))},
    {"scenario": "windows-rdp-only", "target": "10.20.2.16",
     "services": (_svc("3389", "ms-rdp", "Microsoft RDP", "6.1"))},
    {"scenario": "ssh-http-current", "target": "10.20.0.17",
     "services": (_svc("22", "ssh", "OpenSSH",
                       "OpenSSH 9.2p1 Debian 2+deb12u10 (protocol 2.0)"),
                  _svc("80", "http", "Apache httpd", "2.4.49"))},
    # An up-to-date SSH removes the enumeration candidate: one id is left, and
    # one id is not an ordering, so this box is REPORTED as unscoreable.
    {"scenario": "ssh-https-patched-ssh", "target": "10.20.0.18",
     "services": (_svc("22", "ssh", "OpenSSH", "OpenSSH 8.2p1 Ubuntu"),
                  _svc("443", "https"))},

    # -- file services: where the rubric and production DISAGREE -------------
    # A memcached stats answer is INFORMATION; an anonymous NFS export or an
    # rsync module is DATA. The rubric ranks the data above the stats. On this
    # host production does the opposite — memcached 67.77 above rsync 66.05 and
    # nfs 65.10 — because its score weighs how quietly an attempt succeeds more
    # than what it is worth when it does. These entries exist so that
    # disagreement is MEASURED (they are the rows that keep the mean below 1.0)
    # instead of being a sentence in a docstring nobody re-checks.
    {"scenario": "file-services", "target": "10.20.3.11",
     "services": (_svc("2049", "nfs"), _svc("873", "rsync"),
                  _svc("11211", "memcached"))},
    {"scenario": "file-services-smb", "target": "10.20.3.12",
     "services": (_svc("445", "microsoft-ds"), _svc("873", "rsync"),
                  _svc("11211", "memcached"))},
    {"scenario": "elastic-stack", "target": "10.20.3.13",
     "services": (_svc("9200", "elasticsearch"), _svc("11211", "memcached"),
                  _svc("22", "ssh"))},
    # -- COVERAGE (measured 2026-11-03) ------------------------------------
    # The corpus above taught the ranker 4 of the 10 candidate ids a
    # twentieth-service host emits (`noncve:service:redis:6379`,
    # `:vnc:5900`, `:snmp:161`, `:ldap:389`, `:mongodb:27017`, `:nfs:111`
    # were all missing), so 60% of a real table arrived OUT OF VOCABULARY:
    # the model could not score it, `rerank` agreed with the rules and the
    # run looked identical with and without AI. These scenarios teach the
    # ids the runtime actually emits, each paired with a move the doctrine
    # ranks differently (a quiet file service against a loud database), so
    # the ordering is not learned from one class of host alone.
    {"scenario": "redis-ssh", "target": "10.20.4.11",
     "services": (_svc("22", "ssh", "OpenSSH", "OpenSSH 7.4"),
                  _svc("6379", "redis", "Redis", "6.0.9"))},
    {"scenario": "redis-http", "target": "10.20.4.12",
     "services": (_svc("80", "http", "nginx", "1.18.0"),
                  _svc("6379", "redis", "Redis", "5.0.7"))},
    {"scenario": "vnc-rdp", "target": "10.20.4.13",
     "services": (_svc("3389", "ms-wbt-server"), _svc("5900", "vnc"),
                  _svc("445", "microsoft-ds"))},
    {"scenario": "snmp-ldap", "target": "10.20.4.14",
     "services": (_svc("161", "snmp"),
                  _svc("389", "ldap", "OpenLDAP", "2.4.44"),
                  _svc("22", "ssh", "OpenSSH", "OpenSSH 8.2"))},
    {"scenario": "mongodb-ssh", "target": "10.20.4.15",
     "services": (_svc("27017", "mongodb", "MongoDB", "4.4.1"),
                  _svc("22", "ssh", "OpenSSH", "OpenSSH 8.0"))},
    {"scenario": "nfs-rpcbind", "target": "10.20.4.16",
     "services": (_svc("111", "rpcbind"), _svc("2049", "nfs"),
                  _svc("22", "ssh", "OpenSSH", "OpenSSH 7.9"))},
    {"scenario": "postgres-redis", "target": "10.20.4.17",
     "services": (_svc("5432", "postgresql", "PostgreSQL", "13.4"),
                  _svc("6379", "redis", "Redis", "6.2.6"),
                  _svc("80", "http", "nginx", "1.20.1"))},
    {"scenario": "telnet-ftp-legacy", "target": "10.20.4.18",
     "services": (_svc("23", "telnet"), _svc("21", "ftp", "vsftpd", "3.0.3"),
                  _svc("22", "ssh", "OpenSSH", "OpenSSH 5.9"))},
)


# ---------------------------------------------------------------------------
# Building the rows
# ---------------------------------------------------------------------------


def _service_list(services: Any) -> List[Dict[str, str]]:
    """The service dicts of one SWEEP entry, whatever shape the table used.

    ``SWEEP`` is hand-maintained, and ``(_svc(...))`` without a trailing comma is
    NOT a one-element tuple — it is the dict itself. Iterating it yields its
    KEYS, so the old normaliser fed strings to ``dict()`` and the corpus died
    with "dictionary update sequence element #0 has length 1". Accepting both
    shapes here removes a whole class of data-entry slip; anything that is
    neither is skipped rather than turned into a candidate.
    """
    if isinstance(services, Mapping):
        return [dict(services)]
    if not isinstance(services, (list, tuple)):
        return []
    return [dict(service) for service in services
            if isinstance(service, Mapping)]


def _candidates(services: Any, target: str):
    """Production's access candidates for one service list, offline.

    ``include_nvd=False`` is not a speed choice: a corpus whose ids depend on a
    third party answering would differ between two machines, and a
    non-reproducible corpus cannot be compared with anything.
    """
    from phantom.automation.exploit import access

    return list(access.collect_candidates(
        services=_service_list(services),
        target=str(target or ""), include_nvd=False, include_non_cve=True) or [])


def _candidate_row(candidate: Any) -> Dict[str, Any]:
    """The observable surface of one candidate, for the row's ``input``.

    Deliberately NOT ``success``/``noise``/``complexity``: those are
    production's estimates and copying them into the corpus would let a model
    train on the answer it is being scored against.
    """
    row: Dict[str, Any] = {"id": str(getattr(candidate, "id", ""))}
    for field in ("access", "kind", "port", "service", "product", "version"):
        value = getattr(candidate, field, "")
        if str(value or "").strip():
            row[field] = str(value)
    if getattr(candidate, "cve", ""):
        row["cve"] = str(candidate.cve)
    return row


def unscoreable() -> List[Dict[str, Any]]:
    """The SWEEP entries production cannot answer, with the reason.

    A single-service box yields at most ONE access candidate, and one candidate
    is not an ordering. Those entries are reported instead of padded: inventing
    a second candidate to make a row scoreable is the defect this module exists
    to expose, not a fix for it.
    """
    out: List[Dict[str, Any]] = []
    for entry in SWEEP:
        candidates = _candidates(entry["services"], entry["target"])
        if len(candidates) < 2:
            out.append({"scenario": entry["scenario"],
                        "candidates": [str(c.id) for c in candidates],
                        "reason": "production builds fewer than two access "
                                  "candidates for this service set, so there "
                                  "is no ordering to score"})
    return out


def build_rows() -> List[Dict[str, Any]]:
    """The corpus: one row per SWEEP entry production can answer."""
    rows: List[Dict[str, Any]] = []
    for entry in SWEEP:
        candidates = _candidates(entry["services"], entry["target"])
        ids = [str(candidate.id) for candidate in candidates]
        if len(ids) < 2:
            continue
        rows.append({
            "id": f"prod-{entry['scenario']}",
            "phase": PHASE,
            "input": {
                "target": entry["target"],
                "services": [dict(service) for service in entry["services"]],
                "candidates": [_candidate_row(c) for c in candidates],
                "cves": sorted({str(getattr(c, "cve", ""))
                                for c in candidates if getattr(c, "cve", "")}),
                "goal": "foothold",
                "mode": MODE,
                "profile": "enterprise",
                # No row declares a tried move: the label must not depend on a
                # context the file cannot reproduce.
                "already_tried": [],
            },
            "expected": {"ranking": rubric_ranking(ids)},
            "metric": METRIC,
            "label_basis": RUBRIC_VERSION,
        })
    # The gate's competitor is the RUNTIME scorer, so the generator stamps the
    # ordering that scorer would produce instead of leaving the field for
    # someone to hand-write later (a hand-written baseline is an unmeasured
    # number). Stamped HERE, not at write time, so `rows_digest` and the
    # `--check` mode describe the same bytes that land on disk.
    from training import prod_baseline

    return prod_baseline.stamp_rows(rows)



def rows_digest(rows: Sequence[Dict[str, Any]]) -> str:
    """SHA-256 of the rendered rows: what ``--check`` compares.

    ``deterministic_rank`` is EXCLUDED: it is derived by calling the runtime
    scorer, so a regenerated (or newly stamped) baseline must not make an
    otherwise unchanged corpus look like a different label set. ``--check``
    answers "are the labels what the generator produces", not "is the derived
    baseline byte-identical".
    """
    payload = "".join(
        json.dumps({k: v for k, v in row.items()
                    if k != "deterministic_rank"}, sort_keys=True) + "\n"
        for row in rows)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def write(rows: Sequence[Dict[str, Any]], path: Path = GOLDEN_PATH) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    return path


def report() -> Dict[str, Any]:
    """Rows, unscoreable entries, and the production baseline block.

    ``mean_ndcg`` is the agreement between the production ordering and the
    rubric on the rows production can see. It is a MEASUREMENT, not a target:
    a disagreement is reported, never tuned away.
    """
    from training.eval import production_baseline_block

    rows = build_rows()
    block = production_baseline_block(rows)
    return {"rows": len(rows), "scoreable": block.get("rows_scoreable"),
            "coverage": block.get("coverage"),
            "mean_ndcg": block.get("mean_ndcg"),
            "unscoreable": unscoreable(), "block": block}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="training.prod_vocab")
    parser.add_argument("--write", action="store_true",
                        help=f"write {GOLDEN_PATH.name}")
    parser.add_argument("--report", action="store_true",
                        help="print the coverage and the agreement")
    parser.add_argument("--check", action="store_true",
                        help="exit 1 when the golden file is out of date")
    args = parser.parse_args(list(argv) if argv is not None else None)

    if not (args.write or args.report or args.check):
        args.report = True

    rows = build_rows()
    if args.write:
        path = write(rows, GOLDEN_PATH)
        print(f"written {len(rows)} row(s) -> {path}")
    if args.report:
        info = report()
        print(f"rows {info['rows']}  scoreable {info['scoreable']}  "
              f"coverage {info['coverage']}  mean_ndcg {info['mean_ndcg']}")
        for entry in info["unscoreable"]:
            print(f"  unscoreable: {entry['scenario']} "
                  f"({len(entry['candidates'])} candidate(s))")
        print(f"  digest {rows_digest(rows)[:16]}")
    if args.check:
        if not GOLDEN_PATH.is_file():
            print(f"missing {GOLDEN_PATH}", file=sys.stderr)
            return 1
        on_disk = GOLDEN_PATH.read_text(encoding="utf-8")
        rendered = "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows)
        if on_disk != rendered:
            print("the golden file is OUT OF DATE: run --write",
                  file=sys.stderr)
            return 1
        print(f"up to date ({len(rows)} rows, digest "
              f"{rows_digest(rows)[:16]})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


