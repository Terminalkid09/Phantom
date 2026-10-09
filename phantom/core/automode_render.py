"""
automode_render.py — event rendering for the auto-mode CLI stream.

The wording of an event belongs to the shared contract
(phantom.core.stream_contract); this module only maps the rendered level to
the notifier channel and fans the same event out to local frontends
(Electron). automode.py, the swarm stream and the API/UI therefore cannot
drift into three different explanations of the same event.
"""

from __future__ import annotations

from typing import Callable, Optional

from phantom.utils.notifier import notifier


def emit_rendered(rendered) -> None:
    """Print one rendered event on the CLI (level -> notifier channel)."""
    for line in rendered.lines:
        if rendered.level == "success":
            notifier.success(line)
        elif rendered.level == "warn":
            notifier.warn(line)
        elif rendered.level == "error":
            notifier.error(line)
        else:
            notifier.info(line)


def stream_agent_event(kind: str, data: dict, verbose: bool = False) -> None:
    """Render an agent event through the shared contract.

    This function used to BE the renderer and knew 12 of the ~40 kinds the
    engine emits: the stall diagnosis ("stuck because X, change angle to
    Y") and every error/recover/gate/llm/shared event were emitted and then
    dropped here, which made a reasoning engagement look like it had gone
    quiet. The vocabulary now lives in phantom.core.stream_contract.
    """
    from phantom.core.stream_contract import render_event
    rendered = render_event(kind, data, verbose=verbose)
    if rendered is None:
        return
    emit_rendered(rendered)


def make_agent_stream(verbose: bool = False,
                      on_event: Optional[Callable[[str, dict], None]] = None):
    """Factory for the shared agent event stream.

    The CLI renderer remains the default consumer. Electron and other local
    frontends can subscribe to the same events without duplicating the agent.
    """
    def _stream(kind: str, data: dict) -> None:
        if on_event is not None:
            try:
                on_event(kind, data)
            except Exception:
                # A frontend must never interrupt the engagement engine.
                pass
        stream_agent_event(kind, data, verbose=verbose)
    return _stream


def stream_swarm_event(kind: str, data: dict, verbose: bool = False,
                       on_event=None) -> None:
    """Swarm events onto the operator stream, through the SAME contract as
    the agent path.

    This renderer knew two kinds, so `--verbose` was a no-op on the swarm
    path: a swarm run showed task outcomes and nothing about what each task
    reasoned or executed.
    """
    from phantom.core.stream_contract import render_event
    rendered = render_event(kind, data, verbose=verbose)
    if rendered is not None:
        emit_rendered(rendered)
    if on_event is not None:
        try:
            on_event(kind, data)
        except Exception:
            pass
