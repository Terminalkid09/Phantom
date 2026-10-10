"""Contract tests for the LLM command gate (`llm_proposals`).

The user asked for one specific property, so it gets pinned here from every
side: the model may propose, the operator decides, and NOTHING the model
proposes can reach the executor without an explicit acceptance. The tests
also pin the two honesty requirements: the static check is hygiene (it says so),
and an accepted command whose arguments name a host outside the engagement scope
must not run.
"""
import pytest

from phantom.automation import llm_proposals as LP


@pytest.fixture(autouse=True)
def _clean_queue():
    LP.queue.clear()
    yield
    LP.queue.clear()


class TestNothingRunsWithoutTheOperator:
    def test_propose_only_queues_and_never_executes(self, monkeypatch):
        called = []
        monkeypatch.setattr("phantom.core.executor.run_command",
                            lambda *a, **k: called.append(a))
        prop = LP.queue.propose(command="nmap -sV 10.0.0.5", why="version scan")
        assert prop is not None and prop.pending
        assert called == [], "propose() must never execute"
        assert prop.executed is False

    def test_a_pending_proposal_is_not_executed_even_if_called_directly(self):
        prop = LP.queue.propose(command="nmap -sV 10.0.0.5")
        ran = []
        out = LP.execute(prop, target="10.0.0.5",
                         runner=lambda c, t, status=None: ran.append(c) or "ok")
        assert out == "" and ran == []

    def test_a_refused_proposal_is_not_executed(self):
        prop = LP.queue.propose(command="nmap -sV 10.0.0.5")
        LP.queue.refuse(prop.id, "not now")
        ran = []
        out = LP.execute(prop, runner=lambda c, t, status=None: ran.append(c))
        assert out == "" and ran == []

    def test_an_accepted_proposal_runs_through_the_shared_executor(self):
        prop = LP.queue.propose(command="dig example.com ANY +short")
        LP.queue.accept(prop.id)
        seen = {}

        def runner(cmd, target, status=None):
            seen["cmd"], seen["target"] = cmd, target
            return "1.2.3.4"

        out = LP.execute(prop, target="example.com", runner=runner)
        assert out == "1.2.3.4"
        assert seen == {"cmd": "dig example.com ANY +short",
                        "target": "example.com"}

    def test_the_module_delegates_to_the_project_executor_by_default(self):
        """No private execution path: the default runner IS run_command."""
        import inspect

        from phantom.core import executor
        source = inspect.getsource(LP.execute)
        assert "from phantom.core import executor" in source
        assert "run_command" in source
        assert callable(executor.run_command)

    def test_a_runner_that_raises_does_not_propagate(self):
        prop = LP.queue.propose(command="nmap 10.0.0.5")
        LP.queue.accept(prop.id)

        def boom(*_a, **_k):
            raise RuntimeError("executor exploded")

        assert LP.execute(prop, runner=boom) == ""


class TestTheDecisionIsRecordedAndFinal:
    def test_accept_records_who_decided(self):
        prop = LP.queue.propose(command="whois example.com")
        ok, msg = LP.queue.accept(prop.id, decided_by="operator@cli")
        assert ok and "accepted" in msg
        assert prop.state == LP.ACCEPTED and prop.decided_by == "operator@cli"

    def test_a_decided_proposal_cannot_be_decided_again(self):
        prop = LP.queue.propose(command="whois example.com")
        LP.queue.accept(prop.id)
        ok, msg = LP.queue.refuse(prop.id, "changed my mind")
        assert ok is False and "already accepted" in msg
        assert prop.state == LP.ACCEPTED

    def test_refuse_keeps_the_reason(self):
        prop = LP.queue.propose(command="hydra -l root 10.0.0.5 ssh")
        ok, _ = LP.queue.refuse(prop.id, "too loud for this engagement")
        assert ok and prop.state == LP.REFUSED
        assert prop.decision_reason == "too loud for this engagement"

    def test_unknown_ids_are_refused_not_created(self):
        ok, msg = LP.queue.accept(999)
        assert ok is False and "unknown" in msg
        assert LP.queue.all() == []

    def test_the_result_of_an_execution_is_stored_on_the_proposal(self):
        prop = LP.queue.propose(command="dig example.com")
        LP.queue.accept(prop.id)
        LP.queue.record_result(prop.id, ok=True, excerpt="1.2.3.4")
        assert prop.executed and prop.result_ok is True
        assert "1.2.3.4" in prop.result_excerpt


class TestStaticHygiene:
    def test_empty_multiline_and_absurd_commands_are_dropped(self):
        assert LP.queue.propose(command="") is None
        assert LP.queue.propose(command="   ") is None
        assert LP.queue.propose(command="a\nb") is None
        assert LP.queue.propose(command="x" * (LP.MAX_COMMAND_LEN + 1)) is None
        assert LP.queue.all() == []
        assert LP.queue.stats()["static_rejected"] == 4

    def test_the_check_is_documented_as_hygiene_not_security(self):
        doc = LP.static_reject.__doc__ or ""
        assert "Hygiene" in doc or "hygiene" in doc
        assert "not security" in (LP.__doc__ or "").lower() or \
            "HYGIENE, not security" in (LP.__doc__ or "")

    def test_one_line_commands_are_kept_verbatim(self):
        cmd = "nmap -Pn -sV --top-ports 100 10.0.0.5"
        prop = LP.queue.propose(command="  " + cmd + "  ")
        assert prop.command == cmd


class TestTheCommandOwnArgumentsAreScopeChecked:
    """The executor gates on the SESSION target; the arguments are on us."""

    def test_a_host_outside_the_scope_is_found(self):
        bad = LP.out_of_scope_hosts(
            "nmap -sV evil.example.net", ["10.0.0.0/24"],
            check=lambda host, scope: host == "10.0.0.5")
        assert bad == ["evil.example.net"]

    def test_an_in_scope_host_passes(self):
        bad = LP.out_of_scope_hosts(
            "nmap -sV 192.168.1.10", ["192.168.1.0/24"],
            check=lambda host, scope: host.startswith("192.168.1."))
        assert bad == []

    def test_no_scope_declared_means_nothing_to_check(self):
        assert LP.out_of_scope_hosts("nmap evil.example.net", []) == []

    def test_an_unresolvable_host_is_not_an_authorization(self):
        def raiser(host, scope):
            raise RuntimeError("dns down")

        assert LP.out_of_scope_hosts("nmap maybe.example.net", ["10.0.0.0/24"],
                                     check=raiser) == ["maybe.example.net"]

    def test_an_out_of_scope_command_never_reaches_the_runner(self):
        prop = LP.queue.propose(command="nmap -sV evil.example.net")
        LP.queue.accept(prop.id)
        ran = []
        out = LP.execute(
            prop, target="10.0.0.5",
            runner=lambda c, t, status=None: ran.append(c),
            scope=["10.0.0.0/24"])
        assert out == "" and ran == []

    def test_file_like_tokens_are_not_mistaken_for_hosts(self):
        assert LP.hosts_in_command("nmap -oX out.xml --script recon.txt") == []
        assert LP.hosts_in_command("dig example.com") == ["example.com"]
        assert LP.hosts_in_command("nmap 10.0.0.5") == ["10.0.0.5"]


class TestTheQueueIsBoundedAndVisible:
    def test_the_queue_evicts_decided_items_before_pending_ones(self):
        q = LP.ProposalQueue(max_proposals=3)
        d1 = q.propose(command="cmd d1")
        q.accept(d1.id)
        d2 = q.propose(command="cmd d2")
        q.accept(d2.id)
        p1 = q.propose(command="cmd p1")
        p2 = q.propose(command="cmd p2")
        assert len(q.all()) <= 3
        # the two undecided proposals are still there, and so is the verdict
        # of the newest decided one; the OLDEST decided one made room
        assert {p1.id, p2.id} == {p.id for p in q.pending()}
        assert d1.id not in {p.id for p in q.all()}
        assert d2.id in {p.id for p in q.all()}

    def test_render_shows_command_verdict_and_reason(self):
        prop = LP.queue.propose(command="nmap -sV 10.0.0.5",
                                why="version scan")
        LP.queue.refuse(prop.id, "too loud")
        text = LP.render()
        assert "nmap -sV 10.0.0.5" in text and "REFUSED" in text
        assert "version scan" in text and "too loud" in text

    def test_render_of_an_empty_queue_says_so(self):
        assert LP.render() == "no model command proposals"

    def test_stats_count_every_state(self):
        a = LP.queue.propose(command="cmd a")
        b = LP.queue.propose(command="cmd b")
        LP.queue.propose(command="")
        LP.queue.accept(a.id)
        LP.queue.refuse(b.id, "no")
        LP.queue.record_result(a.id, ok=True, excerpt="ok")
        stats = LP.queue.stats()
        assert stats["proposed"] == 2 and stats["static_rejected"] == 1
        assert stats["accepted"] == 1 and stats["refused"] == 1
        assert stats["executed"] == 1 and stats["pending"] == 0


class TestAdvisorIntegration:
    def test_propose_commands_queues_pending_and_journals_them(self, monkeypatch):
        from phantom.automation.llm_advisor import LLMAdvisor
        from phantom.automation import llm_journal

        llm_journal.journal.clear()
        advisor = LLMAdvisor(enabled=True)
        monkeypatch.setattr(advisor, "available", lambda: True)
        monkeypatch.setattr(
            advisor, "_generate_commands",
            lambda wm, limit=5: '[{"command": "dig example.com MX", '
                               '"why": "mail provider"}, '
                               '{"command": "a\\nb", "why": "bad"}]')
        props = advisor.propose_commands(object(), limit=5, agent="test")
        assert len(props) == 1 and props[0].pending

        entries = llm_journal.journal.entries(kind="propose-command")
        assert len(entries) == 1
        verdicts = [(p["verdict"], p.get("drop_reason", ""))
                    for p in entries[0].proposals]
        assert ("pending", "") in verdicts
        assert ("dropped", "multi-line") in verdicts
        # a pending proposal is not a refusal: nothing was refused YET
        assert entries[0].dropped == [p for p in entries[0].proposals
                                      if p["verdict"] == "dropped"]

    def test_the_two_channels_have_separate_strict_parsers(self):
        """A command must not become a capability id, nor the reverse."""
        from phantom.automation.llm_advisor import LLMAdvisor as A
        assert A._parse('[{"command": "nmap 10.0.0.5"}]') == []
        assert A._parse('[{"capability_id": "scan", "reason": "r"}]') == [
            {"capability_id": "scan", "reason": "r"}]
        assert A._parse_commands(
            '[{"capability_id": "scan", "reason": "r"}]') == []
        assert A._parse_commands('[{"command": "nmap 10.0.0.5"}]') == [
            {"command": "nmap 10.0.0.5", "why": ""}]
        # an injected field on the command channel is ignored too
        assert A._parse_commands(
            '[{"command": "id", "action": "run", "why": "w"}]') == [
            {"command": "id", "why": "w"}]

    def test_an_unavailable_advisor_proposes_nothing(self, monkeypatch):
        from phantom.automation.llm_advisor import LLMAdvisor
        advisor = LLMAdvisor(enabled=True)
        monkeypatch.setattr(advisor, "available", lambda: False)
        assert advisor.propose_commands(object()) == []

    def test_a_failing_model_call_proposes_nothing_and_journals_the_error(
            self, monkeypatch):
        from phantom.automation.llm_advisor import LLMAdvisor
        from phantom.automation import llm_journal

        llm_journal.journal.clear()
        advisor = LLMAdvisor(enabled=True)
        monkeypatch.setattr(advisor, "available", lambda: True)

        def boom(wm, limit=5):
            raise RuntimeError("model offline")

        monkeypatch.setattr(advisor, "_generate_commands", boom)
        assert advisor.propose_commands(object()) == []
        assert llm_journal.journal.entries(kind="propose-command")[0].error
