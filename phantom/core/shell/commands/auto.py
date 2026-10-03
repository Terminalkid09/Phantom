"""Autonomy commands: auto (kill chain) and agent (campaigns)."""
from __future__ import annotations

import os
import sys
import time

from phantom.core.session import session
import phantom.core.shell as _sh  # live console: _sh.console resolves the package attr at call time (test patch point)
from phantom.utils.notifier import notifier


def _announce_profile_coverage(profile: str, goal: str = "") -> None:
    """Warn when the chosen profile cannot reach its own declared phases.

    ``check_profile_target`` already reports a profile that contradicts
    the TARGET. This is the other half: a profile whose chain or phases
    no longer resolve (a renamed capability, a fact with no producer)
    would otherwise just make the plan stop with "no affordable path to
    goal" and no explanation. The audit is cheap and read-only, so it is
    announced ONCE, before the run, and never blocks it.

    With ``goal`` it also reports (profile, goal) pairs that cannot
    succeed as configured — a mobile target cannot beacon, 'impact' needs
    its config opt-in — so the operator learns it up front.
    """
    try:
        from phantom.automation.swarm.coverage import (
            coverage_for_profile, feasibility_warnings)
        row = coverage_for_profile(profile)
    except Exception:
        return
    for warn in feasibility_warnings(profile, goal):
        notifier.warn(warn)
    if not row.chain:
        return
    problems = []
    if row.unreachable:
        problems.append(f"unreachable phases: {', '.join(row.unreachable)}")
    if row.thin_caps_missing:
        problems.append("thin-surface capabilities missing: "
                        f"{', '.join(row.thin_caps_missing)}")
    if problems:
        notifier.warn(f"Profile '{profile}' has a capability coverage gap "
                      f"({' ; '.join(problems)}) — those stages will be "
                      f"skipped. Run 'coverage {profile}' for the detail.")


def cmd_auto(shell, arg: str):
    """auto | auto <target[,target...|CIDR]> [flags] - Autonomous kill chain.

    `auto` with NO arguments enters the dedicated AUTO-MODE shell
    (multi-target management, flags, plan/launch/resume, .pm export/
    import — mirrors the Electron Auto-Mode panel, like `c2` for the
    C2). With arguments it runs the chain directly.

    Classifies each target (ip/domain/url/email/username/phone) and
    drives the full chain to beacon injection + persistence, then hands
    the beacon to the operator in the C2 terminal. Identity targets
    converge through OSINT -> breach -> persona -> phish -> victim_ip.

    Flags:
      --stealth     paranoid OPSEC: slower, minimal footprint, skips
                    loud tools (mutually exclusive with --aggressive)
      --aggressive  noisy + fast: online brute force, loud tools, broad
                    enumeration (mutually exclusive with --stealth)
      --speed       opportunistic: exploit the first viable opening
                    without raising detection (combines with either)
      --plan        dry-run: print the planned chain, execute nothing
      --verbose     stream the live reasoning trace while running:
                    inferences, hypotheses formed, confirmations and
                    refutations as facts arrive
      -a | -aN      sub-agents: -a = auto-decide, -a2 = 2 agents,
                    --agents N = explicit (multi-target fan-out or
                    same-target phase workers)
      --llm         optional local-LLM advisor: proposes extra
                    hypotheses only (never executes); requires
                    PHANTOM_LLM_MODEL=<path-to-gguf> — try a Qwen2.5
                    Instruct GGUF, swap the file to scale reasoning
      --resume <cp> resume an interrupted run from its auto-mode
                    checkpoint (extract from a .pm with import-session)

    Every run writes a checkpoint each wave under data/sessions/auto_*/
    and can be shared as a single .pm with export-session.

    Examples:
      auto 192.168.1.1
      auto 10.0.0.0/24
      auto bob@corp.com --stealth
      auto +391234567890 --speed
      auto host1,host2 -a3
      auto 192.168.1.1 --verbose
      auto bob@corp.com --resume data/sessions/auto_1700000000/checkpoint.json
    """
    if not arg.strip():
        # `auto` with no arguments: dedicated AUTO-MODE shell (like `c2`)
        notifier.status("Entering AUTO-MODE interface...")
        from phantom.core.auto_shell import run_auto_shell
        run_auto_shell()
        return

    from phantom.core.automode import run_auto_mode

    import argparse
    parser = argparse.ArgumentParser(prog="auto", add_help=False)
    parser.add_argument("targets", nargs="*", default=[],
                        help="Target(s) or CIDR range")
    parser.add_argument("--stealth", action="store_true", default=False,
                        help="paranoid OPSEC (mutually exclusive with --aggressive)")
    parser.add_argument("--aggressive", action="store_true", default=False)
    parser.add_argument("--speed", action="store_true", default=False)
    parser.add_argument("--reason", default="", metavar="PROFILE",
                        choices=["", "balanced", "stealth_first",
                                 "evidence_first", "force_first"],
                        help="REASONING objective: balanced (default), "
                             "stealth_first (buy quiet), evidence_first "
                             "(buy information), force_first (only sane "
                             "with --aggressive)")
    parser.add_argument("--identity-active", dest="identity_active",
                        action="store_true", default=False,
                        help="DEDICATED consent for ACTIVE identity probes "
                             "(password-reset enumeration, SMTP RCPT email "
                             "verification). Separate from --aggressive; "
                             "without it those probes refuse. Only use on "
                             "targets you are authorised to probe")
    parser.add_argument("--cell-loop", dest="cell_loop",
                        action="store_true", default=True,
                        help="CELL LOOP (always on): the cell roster is the "
                             "AUTHORITY for every goal; the flag is accepted "
                             "for compatibility")
    parser.add_argument("--cell-stages", dest="cell_stages", default="",
                        metavar="G1,G2",
                        help="constrain the roster to these GOALS "
                             "(comma-separated; trialling only — the "
                             "roster stays the authority)")
    parser.add_argument("--oM", "--only-markdown", dest="only_markdown",
                        action="store_true", default=False,
                        help="LEARNING MODE: draft markdown proposals in "
                             "docs/evolution/ instead of authoring code "
                             "(no LLM, no lab; separate daily budget)")
    parser.add_argument("--plan", action="store_true", default=False,
                        help="dry-run: show the planned chain, execute nothing")
    parser.add_argument("--verbose", action="store_true", default=False,
                        help="stream the live reasoning trace (inferences, "
                             "hypotheses, confirmations/refutations)")
    parser.add_argument("-a", "--agents", nargs="?", const=0, type=int,
                        default=0, metavar="N",
                        help="sub-agent count: -a (auto) or -a2 / --agents 2")
    parser.add_argument("--goal", default="deliver",
                        choices=["deep", "deliver", "complete_kill_chain",
                                 "footprint", "beacon", "creds", "web",
                                 "identity", "post_exploit", "ad",
                                 "crack", "lateral", "cleanup"],
                        help="override the terminal goal "
                             "(deep = deliver + post_exploit + ad + "
                             "crack + lateral in one run; default: deliver)")
    parser.add_argument("--profile", default="enterprise",
                        choices=["smb", "enterprise", "cloud", "financial",
                                 "government", "mobile"])
    parser.add_argument("--force-profile", dest="force_profile",
                        action="store_true", default=False,
                        help="keep --profile even when it contradicts the "
                             "target class (--profile mobile on a PC, a "
                             "machine profile on a phone): the coherence "
                             "check is announced, not enforced")
    parser.add_argument("--resume", default="", metavar="CHECKPOINT",
                        help="resume a run from an auto-mode checkpoint "
                             "(extract it from a .pm with import-session)")
    parser.add_argument("--llm", action="store_true", default=False,
                        help="optional local-LLM advisor (requires "
                             "PHANTOM_LLM_MODEL=<path-to-gguf>): non-gating "
                             "hypothesis suggestions, never executes anything")
    parser.add_argument("--experience", dest="experience",
                        action="store_true", default=None,
                        help="cross-engagement LEARNING memory (default: "
                             "automation.experience, on): episodes persist in "
                             "data/experience_cases.json so a wall hit once "
                             "is not hit the same way again — local disk only")
    parser.add_argument("--no-experience", dest="experience",
                        action="store_false", default=None,
                        help="keep the learning memory run-only for this "
                             "run (nothing written to disk)")
    parser.add_argument("--force-network", dest="force_network",
                        action="store_true", default=False,
                        help="CIDR/range inputs engage the FULL chain on "
                             "every discovered host (default: discovery "
                             "only). Loud and broad: use only on "
                             "authorized ranges.")
    parser.add_argument("--allow-install", dest="allow_install",
                        action="store_true", default=False,
                        help="CONSENT to install missing tools BEFORE the "
                             "run (apt/brew/choco/pip in user scope). Off by "
                             "default: nothing installs silently, and never "
                             "mid-engagement")
    parser.add_argument("--swarm", action="store_true", default=False,
                        help="swarm orchestration: fact-driven tasks over a "
                             "shared blackboard (orchestrator + worker "
                             "agents) instead of the single-agent chain")
    parser.add_argument("--chain", default="",
                        choices=["", "footprint", "identity", "full", "deep",
                                 "web", "creds"],
                        help="swarm chain template (with --swarm only); "
                             "empty = derive it from --profile (mobile "
                             "opens with the scan, cloud is identity-led)")
    parser.add_argument("--no-resilient", dest="no_resilient",
                        action="store_true", default=False,
                        help="ONE-SHOT beacon stager: do NOT schedule a "
                             "retry when the first C2 download fails. The "
                             "default is resilient (the stager retries on "
                             "its own until the C2 answers, which is what "
                             "makes delivery survive the server being down); "
                             "opt out only when the retry artefact must not "
                             "exist (max-OPSEC engagements)")
    parser.add_argument("--platform", default="",
                        metavar="PLATFORM",
                        help="social platform of a username target "
                             "(instagram|tiktok|x|github): with a tty, "
                             "shows the profile preview (avatar URL, bio, "
                             "follower counts) for one confirmation before "
                             "launch — beats 2 hours of OSINT on the wrong "
                             "person")

    try:
        args = parser.parse_args(arg.split())
    except SystemExit:
        return

    if args.stealth and args.aggressive:
        notifier.error(
            "--stealth and --aggressive are mutually exclusive.",
            hint="pick one: --stealth (quiet, minimal footprint) or "
                 "--aggressive (noisy, faster)")
        return
    if args.agents is not None and args.agents < 0:
        notifier.error("Agent count must be >= 1.",
                       hint="use -a for auto-decide, or --agents N with "
                            "N >= 1")
        return

    targets = [t.strip() for t in args.targets if t.strip()]

    # Start-gate: precise username + explicit platform + a tty means the
    # operator KNOWS who they mean — show the profile preview (avatar
    # URL, bio, follower counts, direct link) for one confirmation.
    # Wrong-person OSINT costs hours; this question costs seconds.
    if (args.platform and len(targets) == 1 and not args.plan
            and sys.stdin.isatty() and sys.stdout.isatty()):
        try:
            from phantom.automation.guidance.targets import classify_target
            if classify_target(targets[0]) == "username":
                from phantom.automation.social.recon import (
                    present_candidate, preview_profile)
                _prof = preview_profile(targets[0], args.platform)
                _sh.console.print(
                    "\n[bold cyan]Identity start-gate "
                    f"({_prof.username} @ {_prof.platform}, "
                    f"{_prof.state}):[/]")
                _sh.console.print(f"[dim]{present_candidate(_prof)}[/]")
                if _prof.link:
                    _sh.console.print(
                        f"[dim]open: {_prof.link}[/]")
                _confirm = input(
                    "\nIs this the right person? [Y/n/stop]: "
                ).strip().lower()
                if _confirm in ("n", "no", "stop"):
                    notifier.warn("Auto-mode cancelled (wrong profile).")
                    return
        except (EOFError, KeyboardInterrupt):
            print()
            notifier.warn("Auto-mode cancelled.")
            return
        except Exception as exc:
            notifier.warn(f"Profile preview failed ({exc}): proceeding "
                          f"without start-gate.")

    # Confirm in interactive mode. The force-network disclaimer defaults
    # to NO (a range-wide assault is the destructive direction).
    if not shell.auto_run and sys.stdin.isatty() and targets and not args.plan:
        mode = ("paranoid" if args.stealth else
                "aggressive" if args.aggressive else "default")
        _sh.console.print(f"\n[bold cyan]Auto-Mode Configuration:[/]")
        _sh.console.print(f"  Target(s):  [white]{', '.join(targets)}[/]")
        _sh.console.print(f"  Mode:       [white]{mode}[/]"
                      f"{' + speed' if args.speed else ''}")
        _sh.console.print(f"  Agents:     [white]{args.agents or 'auto'}[/]")
        if args.force_network and any("/" in t for t in targets):
            _sh.console.print(
                "[bold yellow]  FORCE-NETWORK: full kill-chain cadence on "
                "EVERY discovered host — scans, exploits, brute force. "
                "Use only on authorized ranges.[/]")
            confirm = input("\nEngage the whole range? [y/N]: ").strip().lower()
            if confirm != "y":
                notifier.warn("Auto-mode cancelled.")
                return
        else:
            confirm = input("\nLaunch autonomous kill chain? [Y/n]: ").strip().lower()
            if confirm == "n":
                notifier.warn("Auto-mode cancelled.")
                return

    if targets:
        session.target = targets[0]

    # Consent-gated provisioning: only an explicit --allow-install touches
    # an installer, and only BEFORE the engagement (never mid-run, where a
    # download is noise on the client's wire).
    if args.allow_install and not args.plan:
        from phantom.automation.runtime.provision import (
            CORE_TOOLS, provision_missing)
        from phantom.automation.runtime.toolchain import ToolRegistry
        _report = provision_missing(ToolRegistry(), consent=True,
                                    tools=CORE_TOOLS)
        for _tool in _report["installed"]:
            notifier.success(f"installed {_tool}")
        for _tool, _res in _report["results"].items():
            if not _res.get("ok"):
                notifier.warn(
                    f"{_tool}: {str(_res.get('output', ''))[:140]}")

    if args.swarm:
        from phantom.automation.swarm import chain_for_profile, run_swarm
        from phantom.automation.swarm.llm import LLMApproval
        from phantom.automation.swarm.profile_policy import (
            check_profile_target)
        from phantom.automation.guidance.targets import classify_target
        approval = LLMApproval()
        if args.llm:
            approval.approve_session()
        # profile <-> target coherence, before anything derives from the
        # profile: `--profile mobile` on a host is corrected (and said) so
        # the chain is not built on a posture that cannot fit the target.
        _check = check_profile_target(
            args.profile, [classify_target(t) for t in targets],
            force=args.force_profile)
        if not _check.ok:
            notifier.warn(_check.reason)
        effective_profile = _check.effective
        _announce_profile_coverage(effective_profile, args.goal)
        # the profile decides the chain when no explicit --chain was given
        effective_chain = args.chain or chain_for_profile(effective_profile)
        # plan against the tools this box ACTUALLY has (no hardcoded set)
        from phantom.automation.runtime.provision import (
            CORE_TOOLS, missing as _missing_tools)
        from phantom.automation.runtime.toolchain import ToolRegistry
        real_tools = ToolRegistry()
        _gaps = _missing_tools(real_tools, CORE_TOOLS)
        if _gaps:
            notifier.warn(
                f"Missing recon tools: {', '.join(_gaps)} — capabilities "
                f"that need them are skipped (use --allow-install to "
                f"provision them)")
        # the swarm path used to drop `--verbose` entirely (it printed only
        # the closing summary) and to ignore `--reason` (no-op). Both are
        # wired now, through the SAME renderer as the agent path.
        from phantom.core.automode import _stream_swarm_event
        summary = run_swarm(
            targets, chain=effective_chain, profile=effective_profile,
            aggressive=args.aggressive, llm_approval=approval,
            reason_profile=args.reason, toolchain=real_tools,
            resilient_stager=not args.no_resilient,
            scope_list=list(session.scope) if session.scope else [],
            on_event=lambda k, d: _stream_swarm_event(k, d, args.verbose))
        notifier.info(f"Swarm {effective_chain}: "
                      f"{sum(1 for t in summary['tasks'] if t['status'] == 'done')}"
                      f"/{len(summary['tasks'])} tasks done, "
                      f"+{summary.get('added', 0)} findings committed, "
                      f"{len(summary.get('failures', []))} failures.")
        for t in summary["tasks"]:
            mark = "✓" if t["status"] == "done" else "✗"
            _sh.console.print(f"  {mark} {t['id']} ({t['goal']}) — {t['status']}"
                              f"{(': ' + t['note']) if t.get('note') else ''}")
        return

    run_auto_mode(
        targets=targets,
        aggressive=args.aggressive,
        stealth=args.stealth,
        speed=args.speed,
        plan=args.plan,
        verbose=args.verbose,
        agents=args.agents or 0,
        goal=args.goal,
        profile=args.profile,
        force_profile=args.force_profile,
        llm=args.llm,
        resume=args.resume,
        reason_profile=args.reason,
        resilient_stager=not args.no_resilient,
        identity_active=args.identity_active,
        cell_loop=args.cell_loop,
        cell_stages=[s.strip() for s in args.cell_stages.split(",")
                     if s.strip()],
        only_markdown=args.only_markdown,
        force_network=args.force_network,
        experience=args.experience,
    )


def cmd_agent(shell, arg: str):
    """agent <target[,target...]> [--aggressive] [--goal <goal>] [--max-agents N]
    Autonomous agent campaign (one sub-agent per target).

    The AI-free planner completes the kill chain (scan -> creds -> beacon)
    and, with goal post_exploit, continues through the beacon channel:
    persistence + SYSTEM/root escalation + process injection.
    Targets are auto-classified: ip/domain/url/email/username/phone.
    For identity targets (email/username/phone) the chain runs OSINT ->
    breach lookup -> persona -> phish (email/sms with IP-grabber) ->
    victim_ip -> network chain -> beacon injection + persistence.
    With --deliver the chain stops right after beacon + persistence.
    OPSEC prioritization, sandbox pre-flight, scope enforcement and dual
    reporting (raw audit + sanitized client report). Multi-target targets
    fan out immediately into pooled sub-agents.

    Examples:
      agent 192.168.1.1
      agent 192.168.1.5,192.168.1.6,192.168.1.7
      agent bob@corp.com --aggressive --goal post_exploit
      agent +391234567890 --deliver
    """
    from phantom.automation.agent import run_autonomous, run_campaign
    from phantom.automation.reporting import (
        RawReport, ClientReport, CampaignReport, ReportWriter)
    from phantom.utils.paths import sessions_dir

    import argparse
    parser = argparse.ArgumentParser(prog="agent", add_help=False)
    parser.add_argument("target", nargs="?", default="", help="Target(s), comma-separated")
    parser.add_argument("--aggressive", action="store_true", default=False)
    parser.add_argument("--profile", default="enterprise",
                        choices=["smb", "enterprise", "cloud", "financial",
                                 "government", "mobile"])
    parser.add_argument("--force-profile", dest="force_profile",
                        action="store_true", default=False,
                        help="keep --profile even when it contradicts the "
                             "target class (--profile mobile on a PC, a "
                             "machine profile on a phone)")
    parser.add_argument("--goal", default="complete_kill_chain",
                        choices=["deep", "footprint", "beacon", "creds",
                                 "web",
                                 "identity", "complete_kill_chain", "deliver",
                                 "post_exploit",
                                 "ad", "crack", "lateral", "cleanup"])
    parser.add_argument("--deliver", action="store_true", default=False,
                        help="deliver mode: reach beacon injection + "
                             "persistence, then stop (goal=deliver)")
    parser.add_argument("--cleanup", action="store_true", default=False,
                        help="end the engagement: remove persistence and "
                             "kill the beacons on every target (goal=cleanup)")
    parser.add_argument("--max-agents", type=int, default=3,
                        help="concurrent sub-agents for multi-target campaigns")
    parser.add_argument("--state", default=None,
                        help="checkpoint file: resumes an interrupted "
                             "agent run, or writes checkpoints there")
    parser.add_argument("--state-dir", default=None,
                        help="directory for per-target campaign checkpoints "
                             "(resumes sub-agents that were interrupted)")
    parser.add_argument("--experience", dest="experience",
                        action="store_true", default=None,
                        help="cross-engagement LEARNING memory (default: "
                             "automation.experience, on) — local disk only")
    parser.add_argument("--no-experience", dest="experience",
                        action="store_false", default=None,
                        help="keep the learning memory run-only for this "
                             "run (nothing written to disk)")
    try:
        args = parser.parse_args(arg.split())
    except SystemExit:
        return

    targets = [t.strip() for t in (args.target or "").split(",") if t.strip()]
    if not targets and session.target:
        targets = [session.target]
    if not targets:
        notifier.error("No target set. Provide a target or use 'set target' first.")
        return
    if any(not t for t in targets):
        notifier.error("Empty target in list.")
        return

    # profile <-> target coherence (same rule as `auto`): the profile is
    # the environment, the target is the entity. Corrected posture is
    # announced, never silent; --force-profile keeps the operator's pick.
    from phantom.automation.guidance.targets import classify_target
    from phantom.automation.swarm.profile_policy import check_profile_target
    _check = check_profile_target(
        args.profile, [classify_target(t) for t in targets],
        force=args.force_profile)
    if not _check.ok:
        notifier.warn(_check.reason)
    profile = _check.effective
    _announce_profile_coverage(profile, goal)

    # scope enforcement: the session scope is mandatory for the agent
    scope_list = list(session.scope) if session.scope else []
    if not scope_list:
        notifier.warn("No scope defined: the agent will refuse nothing. "
                      "Set scope with 'set scope <cidr,...>' for real engagements.")

    # experience memory: the entry point resolves the operator's intent
    # (flag wins over config; config default is on). The agent never reads
    # config itself — same contract as llm/evolution.
    from phantom.core.automode import _experience_enabled
    experience_enabled = _experience_enabled(args.experience)

    def _stream(kind: str, data: dict) -> None:
        # ONE renderer: this used to be a fourth, private copy that joined
        # `findings` without the values (so `agent <t>` showed bare keys).
        # The contract marks what is verbose-only; `agent` is not verbose.
        from phantom.core.stream_contract import render_event
        rendered = render_event(kind, {**data, "target": data.get("target")},
                                verbose=False)
        if rendered is None:
            return
        tgt = data.get("target")
        tag = f"[bold blue]{tgt}[/] " if tgt else ""
        for line in rendered.lines:
            _sh.console.print(f"{tag}{line}")

    out_root = os.path.join(sessions_dir(), f"agent_{int(time.time())}")
    writer = ReportWriter(out_root)

    goal = "cleanup" if args.cleanup else args.goal
    if args.deliver:
        goal = "deliver"
        notifier.info("Deliver mode: stop after beacon injection + persistence.")
    if args.cleanup:
        notifier.info("Cleanup mode: persistence removal + beacon exit "
                      "on every target.")

    if len(targets) == 1:
        if args.state and os.path.exists(args.state):
            notifier.info(f"Resuming agent run from checkpoint "
                          f"{args.state}...")
        elif args.state:
            notifier.info(f"Checkpoint target: {args.state}")
        result, agent = run_autonomous(
            target=targets[0], profile=profile,
            aggressive=args.aggressive, goal=goal,
            scope_list=scope_list,
            on_event=_stream, return_agent=True,
            state_path=args.state,
            experience=experience_enabled)
        paths = writer.write(
            RawReport.from_agent(agent), ClientReport.from_agent(agent, profile))
        receipt = getattr(agent, "experience", None)
        if receipt is not None:
            from phantom.automation.agent import experience_receipt
            notifier.info(experience_receipt(receipt))
        notifier.success("Agent run finished. Reports:")
        for k, p in paths.items():
            _sh.console.print(f"  [cyan]{k}[/]: {p}")
        return

    notifier.info(f"Campaign over {len(targets)} targets "
                  f"(pool: {args.max_agents} sub-agents)...")
    campaign = run_campaign(
        targets=targets, profile=profile, aggressive=args.aggressive,
        goal=goal, scope_list=scope_list, max_agents=args.max_agents,
        on_event=_stream, state_dir=args.state_dir,
        experience=experience_enabled)
    per_target = {}
    for t in targets:
        r = campaign["results"].get(t, {})
        a = campaign.get("_agents", {}).get(t)
        if a is not None:
            tdir = os.path.join(out_root, t.replace("/", "_"))
            paths = ReportWriter(tdir).write(
                RawReport.from_agent(a), ClientReport.from_agent(a, profile))
            per_target[t] = {"dir": tdir, **paths}
    cpaths = writer.write_campaign(
        CampaignReport(campaign, profile, per_target))
    notifier.success(
        f"Campaign finished: {campaign['beacons']} beacons, "
        f"{campaign['persistent']} persistent, "
        f"{campaign['pivots']} lateral moves, "
        f"{campaign['ad_domains']} AD domains, "
        f"{campaign['compromised_creds']} creds.")
    for k, p in {**per_target, **cpaths}.items():
        _sh.console.print(f"  [cyan]{k}[/]: {p}")


COMMANDS = {
    "auto": cmd_auto,
    "agent": cmd_agent,
}
