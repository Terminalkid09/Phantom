"""phases.py — the six bounded models this pipeline can train.

One model per phase, not one model for everything: a 1.5B model that only
ranks access candidates is cheaper, faster and easier to evaluate than a
general agent, and a failure in one phase cannot silently degrade another.

Every phase declares:

* ``task``   — what the model is asked to do, in one sentence (this becomes
               the system prompt of its SFT examples);
* ``schema`` — the output contract the runtime validates (``phantom.
               automation.ai.schemas``); a model that violates it is refused;
* ``input``  — the shape of the user message, for dataset builders;
* ``metric`` — the primary evaluation metric the promotion gate uses.

The training target is BEHAVIOUR (format, ranking, extraction), never
memorised facts: CVE/module knowledge is retrieved at runtime from NVD and
the local ExploitDB mirror, so a model never has to be re-trained when the
vulnerability landscape changes.
"""

from __future__ import annotations

from typing import Dict

PHASES: Dict[str, Dict[str, str]] = {
    "exploit": {
        "task": (
            "Given the eligible access candidates for one target, rank them "
            "by expected success and name the single best next attempt. You "
            "may only choose candidate ids that are present in the input, "
            "and you must give a one-sentence reason and an expected success "
            "probability between 0 and 1."
        ),
        "schema": "exploit_rank",
        "input": "target + findings + candidate table",
        "metric": "ndcg",
    },
    "finding": {
        "task": (
            "Normalise one raw observation into a typed finding: kind, key, "
            "value, confidence and the evidence snippet that proves it. If "
            "the observation does not prove a fact, say confidence 0 and do "
            "not invent a value."
        ),
        "schema": "finding_normalize",
        "input": "raw observation text + source",
        "metric": "exact_match",
    },
    "osint": {
        "task": (
            "Given two public profiles, propose whether they are the same "
            "person and list the independent signals that support it. Never "
            "claim identity proof from a username or avatar alone; a single "
            "weak signal is 'probable', not 'confirmed'."
        ),
        "schema": "osint_link",
        "input": "two profile summaries",
        "metric": "brier",
    },
    "social": {
        "task": (
            "Write one short message in the target's language for the given "
            "channel and pretext. No link in the opener, no urgency, no "
            "credential request, no generic greeting: a message a real person "
            "would plausibly write in that thread."
        ),
        "schema": "social_message",
        "input": "channel + pretext + target context",
        "metric": "rubric",
    },
    "scan_parse": {
        "task": (
            "Extract the open ports and service banners from this tool "
            "output. Report only what the output shows; a truncated or empty "
            "output yields an empty list, never a guess."
        ),
        "schema": "scan_parse",
        "input": "tool name + raw output",
        "metric": "exact_match",
    },
    "evolution": {
        "task": (
            "Turn one stable failure record into a triage label: cause class, "
            "whether a new capability would fix it, and the narrowest repair. "
            "Do not propose a change to the execution engine."
        ),
        "schema": "evolution_triage",
        "input": "failure record + surrounding facts",
        "metric": "exact_match",
    },
}

PHASE_ORDER = ("exploit", "finding", "osint", "social", "scan_parse",
               "evolution")

GOLDEN_FILES = {phase: f"{phase}.jsonl" for phase in PHASES}


def phase_config(phase: str) -> Dict[str, str]:
    """Registered phase or a KeyError that names the valid ones."""
    if phase not in PHASES:
        raise KeyError(f"unknown phase {phase!r}; want one of "
                       f"{', '.join(PHASE_ORDER)}")
    return {"phase": phase, **PHASES[phase]}
