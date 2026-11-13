"""
phantom.automation.brain.llm — LLM hypothesizer behind validation gates.

The local model's role is NOT to pick from a menu (the old advisor) but
to GENERATE novel operator chains from the structured WorldModel state —
things no registry contains. Generation is free; authorization is not:
every proposed chain passes the five hard gates in gates.py before it
biases planning, and the composition engine re-derives the chain itself
so the LLM only ever SUGGESTS directions (hypothesis-space shaping),
never executes.

Prompt-injection containment: target-derived data enters the prompt
wrapped as untrusted quoted context with an instruction preamble (same
pattern as the strategic-phishing dossier advisor). A successful
injection can at most steer WHICH legal chain is proposed — gates and
the composition engine still constrain execution.
"""

from __future__ import annotations
