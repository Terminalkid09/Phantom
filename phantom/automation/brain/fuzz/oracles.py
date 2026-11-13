"""
oracles.py — differential oracles for the fuzz driver.

An oracle compares a mutation's response against the BASELINE response
and returns a verdict. Verdicts, not payloads, are the discovery
mechanism: a param that answers differently to `'` vs `''` is
interesting regardless of which specific payload revealed it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional

# server error fingerprints (any DB / template / language)
_ERROR_PATTERNS = [
    (r"SQL syntax.*?MySQL|Warning.*?mysql_|MySQLSyntaxErrorException",
     "sqli", "mysql error surfaced"),
    (r"PostgreSQL.*?ERROR|psycopg2|pg_query", "sqli", "postgres error surfaced"),
    (r"SQLite/JDBC|SQLiteException|SQLITE_ERROR", "sqli", "sqlite error surfaced"),
    (r"Microsoft.*?ODBC|SQLServer JDBC|Unclosed quotation", "sqli",
     "mssql error surfaced"),
    (r"ORA-\d{5}", "sqli", "oracle error surfaced"),
    (r"TemplateSyntaxError|jinja2\.exceptions|smarty", "ssti",
     "template engine error surfaced"),
    (r"Warning: include\(|Failed opening required", "path",
     "php include error surfaced"),
    (r"java\.lang|Traceback \(most recent call last\)|System\.NullReference",
     "ssti", "runtime stack trace surfaced"),
]

_PATH_CONTENT = re.compile(r"root:[x*!]:0:0:|boot loader|\[fonts\]", re.I)
_TIME_DELTA_THRESHOLD = 1.5   # seconds over baseline = time-based signal


@dataclass
class Response:
    """A normalized HTTP response observation."""
    status: int = 0
    body: str = ""
    elapsed: float = 0.0        # seconds
    length: int = 0

    def __post_init__(self) -> None:
        if not self.length:
            self.length = len(self.body or "")


@dataclass
class Verdict:
    oracle: str
    interesting: bool
    detail: str = ""
    family_hint: str = ""

    def to_dict(self) -> dict:
        return {"oracle": self.oracle, "interesting": self.interesting,
                "detail": self.detail, "family_hint": self.family_hint}


class DifferentialOracle:
    """Compares a mutation response against the parameter's baseline."""

    def evaluate(self, baseline: Response, mutated: Response) -> Verdict:
        # 1. error-based: a NEW server error string appeared
        for pattern, family, label in _ERROR_PATTERNS:
            if re.search(pattern, mutated.body or "", re.I) and \
                    not re.search(pattern, baseline.body or "", re.I):
                return Verdict("error_based", True, label, family)

        # 2. path-content oracle: traversal leaked a real file
        if _PATH_CONTENT.search(mutated.body or "") and \
                not _PATH_CONTENT.search(baseline.body or ""):
            return Verdict("content_probe", True,
                           "sensitive file content reflected", "path")

        # 3. reflective-differential: status changed meaningfully
        if baseline.status and mutated.status and \
                baseline.status != mutated.status:
            # a 500 on a mutation is a crash signal; 200->403 is a WAF rule,
            # which is ALSO informative (filter boundary found)
            if mutated.status >= 500:
                return Verdict("status_differential", True,
                               f"baseline {baseline.status} -> "
                               f"{mutated.status} (crash)", "fuzz")
            if mutated.status == 403 and baseline.status == 200:
                return Verdict("filter_boundary", True,
                               "mutation tripped a WAF rule (filter boundary "
                               "mapped — encode differently, do not repeat)",
                               "waf")

        # 4. length-differential: large body change with same status
        if baseline.length and abs(mutated.length - baseline.length) > \
                max(96, baseline.length // 3):
            return Verdict("length_differential", True,
                           f"length {baseline.length} -> {mutated.length}",
                           "fuzz")

        # 5. time-based: response took meaningfully longer
        if mutated.elapsed - baseline.elapsed >= _TIME_DELTA_THRESHOLD:
            return Verdict("time_based", True,
                           f"elapsed {baseline.elapsed:.2f}s -> "
                           f"{mutated.elapsed:.2f}s", "sqli")

        return Verdict("differential", False, "no meaningful difference")
