import argparse
import os
import sys

from phantom.core.shell import PhantomShell
from rich.console import Console

console = Console()

def build_parser() -> argparse.ArgumentParser:
    """The CLI surface, in ONE place.

    Factored out of :func:`main` so it can be INTROSPECTED: the README claims a
    set of flags, and `tests/test_readme_contract.py` compares that set with
    this parser. The two used to live in different worlds — the README
    documented `--agent` and `--no-stealth`, which never existed, and `--agent`
    was even SWALLOWED silently (`parse_known_args` puts unknown options in
    `extra`, where nothing looked at them).

    ``allow_abbrev=False`` closes the back door on that: argparse otherwise
    resolves any unambiguous PREFIX, so `--agent` was accepted as `--agents`
    (with no value, i.e. the default — a typo that changes nothing AND says
    nothing). Now it falls through to :func:`main`'s unknown-option refusal.
    """
    parser = argparse.ArgumentParser(
        description="Phantom offensive Security Framework",
        allow_abbrev=False)
    parser.add_argument("--profile",
                        help="Load engagement profile at startup (manual shell)")
    parser.add_argument("--c2", action="store_true", help="Launch Phantom C2 interface instead of the AUTO-MODE shell")
    parser.add_argument("--manual", action="store_true",
                        help="Launch the MANUAL module shell instead of "
                             "AUTO-MODE (the module workflow is also a "
                             "`manual` mode inside the AUTO shell)")
    parser.add_argument("--auto", nargs="*", metavar="TARGET", default=None,
                        help="AUTO-MODE: with target(s) run the full kill chain "
                             "directly; with no target open the interactive "
                             "AUTO-MODE shell (same as `phantom.auto`)")
    # auto-mode passthrough flags (only meaningful with --auto <target>)
    parser.add_argument("--stealth", action="store_true", help="paranoid OPSEC (auto-mode)")
    parser.add_argument("--aggressive", action="store_true", help="loud, fast exploitation (auto-mode)")
    parser.add_argument("--speed", action="store_true", help="exploit first viable opening (auto-mode)")
    parser.add_argument("--reason", default="", metavar="PROFILE",
                        choices=["", "balanced", "stealth_first",
                                 "evidence_first", "force_first"],
                        help="auto-mode REASONING objective: balanced "
                             "(default), stealth_first (buy quiet), "
                             "evidence_first (buy information), force_first "
                             "(only sane with --aggressive)")
    parser.add_argument("--identity-active", dest="identity_active",
                        action="store_true", default=False,
                        help="auto-mode DEDICATED consent for ACTIVE identity "
                             "probes (reset enumeration, SMTP email verify); "
                             "separate from --aggressive")
    parser.add_argument("--cell-loop", dest="cell_loop", action="store_true",
                        default=True,
                        help="auto-mode CELL LOOP (always on): the cell "
                             "roster is the AUTHORITY for every goal; the "
                             "flag is accepted for compatibility")
    parser.add_argument("--cell-stages", dest="cell_stages", default="",
                        metavar="G1,G2",
                        help="auto-mode: constrain the roster to these GOALS "
                             "(comma-separated, e.g. deliver,post_exploit; "
                             "trialling only — the roster stays the authority)")
    parser.add_argument("--oM", "--only-markdown", dest="only_markdown",
                        action="store_true",
                        help="auto-mode LEARNING MODE: draft markdown proposals "
                             "in docs/evolution/ instead of authoring code "
                             "(no LLM, no lab; separate daily budget)")
    parser.add_argument("--plan", action="store_true", help="dry-run: show plan, execute nothing (auto-mode)")
    parser.add_argument("--verbose", action="store_true", help="stream live reasoning trace (auto-mode)")
    parser.add_argument("-a", "--agents", nargs="?", const=0, type=int, default=0,
                        metavar="N", help="sub-agent count: -a (auto) or -a2 (auto-mode)")
    parser.add_argument("--goal", default="deliver", help="terminal goal (auto-mode, default: deliver)")
    parser.add_argument("--profile-auto", dest="profile_auto", default="enterprise",
                        help="target profile (auto-mode, default: enterprise)")
    parser.add_argument("--resume", default="", metavar="CHECKPOINT",
                        help="resume from an auto-mode checkpoint (auto-mode)")
    parser.add_argument("--resume-latest", dest="resume_latest", action="store_true",
                        help="resume the NEWEST auto-mode checkpoint with nobody "
                             "watching (unattended restart, bounded by a "
                             "persisted counter so a crash loop terminates)")
    parser.add_argument("--supervise", action="store_true",
                        help="auto-mode: keep the run alive WITHOUT anybody "
                             "watching — a crash mid-engagement relaunches it "
                             "from its checkpoint, and so does a run that "
                             "ended cleanly WITHOUT reaching its goal "
                             "(`completed` != goal reached); both are bounded "
                             "by the same persisted counter, and Ctrl+C is a "
                             "stop, never a relaunch")
    parser.add_argument("--max-restarts", dest="max_restarts", type=int,
                        default=3, metavar="N",
                        help="auto-mode --supervise: automatic relaunches "
                             "allowed after a crash (default 3; 0 refuses "
                             "every unattended restart)")
    parser.add_argument("--print-service", dest="print_service", nargs="?",
                        const="host", default="",
                        metavar="{systemd,launchd,schtasks}",
                        help="auto-mode: print the OS service definition for "
                             "THIS invocation to stdout (nothing is written) "
                             "— review it, or redirect it into the unit path")
    parser.add_argument("--install-service", dest="install_service", nargs="?",
                        const="host", default="",
                        metavar="{systemd,launchd,schtasks}",
                        help="auto-mode: WRITE the service definition that "
                             "starts this run after a reboot (it is not "
                             "enabled: the command to enable it is printed)")
    parser.add_argument("--uninstall-service", dest="uninstall_service",
                        nargs="?", const="host", default="",
                        metavar="{systemd,launchd,schtasks}",
                        help="auto-mode: remove the service definition "
                             "(--service-name selects which one)")
    parser.add_argument("--service-name", dest="service_name", default="",
                        metavar="NAME",
                        help="auto-mode service definition: unit name "
                             "(default: one per platform)")
    parser.add_argument("--service-system", dest="service_system",
                        action="store_true",
                        help="auto-mode service definition: a system-level "
                             "unit instead of a per-user one (needs root to "
                             "enable; survives a logout)")
    parser.add_argument("--llm", action="store_true", help="optional local-LLM advisor (auto-mode)")
    parser.add_argument("--experience", action="store_true",
                        help="CROSS-ENGAGEMENT learning memory (auto-mode): "
                             "keep cause->repair experience between runs "
                             "(default: learning is scoped to this run only)")
    parser.add_argument("--evolution", action="store_true",
                        help="SELF-IMPROVEMENT (auto-mode): stable uncovered "
                             "failure patterns spawn a background sub-agent "
                             "that authors a new capability and opens a "
                             "reviewable PR (lab required; max 2 PRs/day)")
    parser.add_argument("--beta", action="store_true",
                        help="BETA CAPABILITIES (auto-mode): fetch open "
                             "auto-evolution PRs, gate them locally and use "
                             "the ones that pass (same full gate, lab "
                             "included; working tree untouched)")
    parser.add_argument("-y", "--yes", action="store_true", help="Run mode sequences without confirmation prompts")
    parser.add_argument("--setup", nargs="?", const="", metavar="TARGET",
                        help="guided setup: 'wsl' for the Windows WSL toolbox "
                             "flow, none for the full wizard (tools, doctor)")
    parser.add_argument("--doctor", action="store_true",
                        help="diagnostics only: python, tools, docker, WSL, "
                             "LLM transport — installs nothing")
    return parser


def main():
    parser = build_parser()
    args, extra = parser.parse_known_args()
    # `parse_known_args` exists so `--auto <t1> <t2>` can take extra TARGETS.
    # Anything else left over that looks like a flag is an option this entry
    # point does not have: refusing it is the difference between "`--agent` did
    # nothing" and "`--agent` does not exist, here is what does".
    unknown = sorted({tok for tok in extra if tok.startswith("-")})
    if unknown:
        from phantom.utils.notifier import notifier
        notifier.error("unknown option(s): " + ", ".join(unknown))
        notifier.info("`phantom --help` lists every flag this entry point "
                      "accepts; extra non-flag arguments after `--auto` are "
                      "treated as targets.")
        sys.exit(2)

    if args.doctor:
        from phantom.utils.setup_wizard import doctor
        doctor()
        return
    if args.setup is not None:
        from phantom.utils.setup_wizard import run_wizard
        sys.exit(run_wizard(args.setup, assume_yes=args.yes))

    # Direct entry points: `phantom.c2` / `phantom.auto` land in the right
    # shell immediately (no flag), matching the `phantom` default.
    argv0 = os.path.basename(sys.argv[0] or "").lower()
    if argv0.startswith("phantom.c2") or (argv0 == "phantom-c2"):
        from phantom.core.c2_shell import run_c2
        run_c2()
        return
    if argv0.startswith("phantom.auto") or (argv0 == "phantom-auto"):
        from phantom.core.auto_shell import run_auto_shell
        run_auto_shell()
        return

    if args.c2:
        from phantom.core.c2_shell import run_c2
        run_c2()
        return

    if (args.print_service or args.install_service
            or args.uninstall_service) and args.auto is None:
        # A unit describes an AUTO-MODE run: without --auto there is no run to
        # describe, and silently ignoring the flag would leave the operator
        # believing a service was written.
        from phantom.utils.notifier import notifier
        notifier.error("--print-service/--install-service/"
                       "--uninstall-service describe an AUTO-MODE run: pass "
                       "them with --auto <targets> (e.g. `phantom --auto "
                       "10.0.0.5 --install-service`)")
        sys.exit(2)

    if args.auto is not None:
        # `phantom --auto` (no target) -> interactive AUTO-MODE shell;
        # `phantom --auto <t1[,t2]...> [flags]` -> run the kill chain now.
        targets = [t for t in (args.auto + extra) if t.strip()]
        # Service definition: render/install/remove the thing that starts this
        # run after a reboot. Handled BEFORE the interactive-shell fallback,
        # because `--print-service` is meaningful with or without a target.
        if (args.print_service or args.install_service
                or args.uninstall_service):
            sys.exit(run_service_command(args, targets))
        if not targets:
            from phantom.core.auto_shell import run_auto_shell
            run_auto_shell()
            return
        from phantom.core.automode import run_auto_mode
        # --resume-latest: the policy lives in utils/auto_resume (never asks
        # a human, never raises). A refusal is announced WITH its reason and
        # the run is not started — that is the point of the counter.
        _resume_counter = ""
        if args.resume_latest and not args.resume:
            from phantom.utils.auto_resume import (counter_path_for,
                                                   plan_resume)
            from phantom.utils.notifier import notifier
            from phantom.utils.session_bundle import latest_checkpoint
            _decision = plan_resume(latest_checkpoint() or "")
            if not _decision.ok:
                notifier.warn(f"--resume-latest: {_decision.reason}")
                return
            notifier.info(f"--resume-latest: riprendo "
                          f"{_decision.checkpoint} "
                          f"(tentativo {_decision.attempt})")
            args.resume = _decision.checkpoint
            _resume_counter = counter_path_for(_decision.checkpoint)
        def _launch(checkpoint: str):
            """One auto-mode attempt, resuming from `checkpoint` when given."""
            return run_auto_mode(
                targets=targets,
                aggressive=args.aggressive,
                stealth=args.stealth,
                speed=args.speed,
                plan=args.plan,
                verbose=args.verbose,
                agents=args.agents or 0,
                goal=args.goal,
                profile=args.profile_auto,
                llm=args.llm,
                experience=args.experience,
                evolution=args.evolution,
                beta=args.beta,
                resume=checkpoint,
                reason_profile=args.reason,
                identity_active=args.identity_active,
                cell_loop=args.cell_loop,
                cell_stages=[s.strip() for s in args.cell_stages.split(",")
                             if s.strip()],
                only_markdown=args.only_markdown,
            )

        if args.supervise:
            # Nobody is watching: a crash at hour three must not end the
            # engagement. The supervisor decides WHEN to relaunch (a crash),
            # `utils/auto_resume` decides WHETHER it may (the persisted
            # budget), and Ctrl+C stays an operator stop.
            from phantom.utils.auto_supervisor import supervise
            from phantom.utils.notifier import notifier

            def _announce(kind: str, payload: dict) -> None:
                """Surface a relaunch/stop; the first launch needs no line."""
                if kind != "launch":
                    notifier.info(f"supervisor: {kind} {payload}")

            def _outcome(result) -> str:
                """The engagement outcome the run itself reported.

                `run_auto_mode` returns its envelope (`outcome`, `label`,
                `goal_reached`, per-target tokens). The supervisor needs it
                to tell an engagement that is DONE from one that stopped
                cleanly having got nowhere: the second kind is unattended
                work, not a finished engagement.
                """
                try:
                    return str((result or {}).get("outcome") or "")
                except Exception:
                    return ""

            _summary = supervise(
                _launch,
                resume=args.resume,
                max_restarts=args.max_restarts,
                counter_path=_resume_counter,
                on_event=_announce,
                outcome_of=_outcome,
            )
            notifier.info(
                f"auto-mode supervised: {_summary['attempts']} attempt(s), "
                f"stopped: {_summary['stopped_reason']}")
            return

        _launch(args.resume)
        if _resume_counter:
            # the run finished (clean or not): the restart budget resets, so
            # the NEXT crash gets its own allowance instead of inheriting a
            # spent counter forever.
            from phantom.utils.auto_resume import note_success
            note_success(_resume_counter)
        return

    if args.manual:
        run_pentest_shell(args)
        return

    # DEFAULT: bare `phantom` opens the AUTO-MODE shell.
    #
    # The module/pentest workflow is a MODE of auto-mode now (`manual` inside
    # the shell, or `phantom --manual`), not a second entry point. Two shells
    # meant two state paths -- target, scope, accumulated knowledge -- and two
    # help tables, and that is exactly how they drifted apart: `run` after an
    # `auto` started from a blank slate. One entry point keeps one source of
    # truth; the human-in-the-loop path is still there, one command away.
    from phantom.core.auto_shell import run_auto_shell
    run_auto_shell()


def build_service_command(args, targets) -> list:
    """The unit's command line: the operator's OWN invocation, verbatim.

    Reconstructed from the PARSED arguments, never from ``sys.argv``: the
    parser has already decided what each flag meant, so nothing here can
    invent an argument or mis-split one. Flags are only carried when the
    operator actually passed them — a unit that hardcodes a default the
    operator never typed is a unit that lies about what the engagement
    agreed to (the defaults are applied by the parser on the way back in).

    ``--supervise --resume-latest`` is the point of the exercise: a boot that
    finds the run dead must relaunch it, and the relaunched process asks
    `utils/auto_resume` for permission from the persisted budget.
    """
    command = [sys.executable or "python", "-m", "phantom.main",
               "--auto", *targets, "--supervise", "--resume-latest"]
    for flag, value in (("--aggressive", args.aggressive),
                        ("--stealth", args.stealth),
                        ("--speed", args.speed),
                        ("--llm", args.llm),
                        ("--experience", args.experience),
                        ("--evolution", args.evolution),
                        ("--beta", args.beta),
                        ("--identity-active", args.identity_active),
                        ("--only-markdown", args.only_markdown),
                        ("--verbose", args.verbose)):
        if value:
            command.append(flag)
    if args.goal and args.goal != "deliver":
        command += ["--goal", args.goal]
    if args.profile_auto and args.profile_auto != "enterprise":
        command += ["--profile-auto", args.profile_auto]
    if args.reason:
        command += ["--reason", args.reason]
    if args.agents:
        command += ["--agents", str(args.agents)]
    stages = [s.strip() for s in (args.cell_stages or "").split(",")
              if s.strip()]
    if stages:
        command += ["--cell-stages", ",".join(stages)]
    if args.max_restarts != 3:
        command += ["--max-restarts", str(args.max_restarts)]
    return command


#: audit kinds for boot-level service definitions. Deliberately the SAME
#: strings as `phantom.automation.decision_audit.KIND_SERVICE_*` (one
#: vocabulary, pinned by tests/test_service_unit_safety.py), without importing
#: the automation package just to open the CLI.
KIND_INSTALLED = "service_unit_installed"
KIND_REMOVED = "service_unit_removed"


def _audit_service(event: str, **fields) -> None:
    """Record a boot-level service change. Never raises.

    Writing (or deleting) a service definition outlives the process and can
    start code at boot: it belongs in the tamper-evident trail next to the
    decisions, not only in scrollback. Best-effort by construction — an audit
    sink must never make the operator lose the action itself.
    """
    try:
        from phantom.automation import decision_audit
        decision_audit.record(event, **fields)
    except Exception:
        pass


def run_service_command(args, targets) -> int:
    """Print, install or remove the OS service definition for this run.

    Returns the exit code. Every refusal is a REASON through the notifier and
    a non-zero code, and nothing is written on a refusal — the one action that
    touches the filesystem is `install_service`.

    `--print-service` writes the unit to stdout and NOTHING else there, so
    `phantom --auto <t> --print-service systemd > unit.service` produces a
    file that can be dropped straight into the unit directory.
    """
    from phantom.utils.service_units import (KINDS, default_name, file_digest,
                                             host_kind, install_service,
                                             plan_service, service_path,
                                             supported, uninstall_service)
    from phantom.utils.notifier import notifier
    from phantom.utils.paths import project_root

    action, kind = "", ""
    for name, value in (("print", args.print_service),
                        ("install", args.install_service),
                        ("uninstall", args.uninstall_service)):
        if value:
            action, kind = name, value
            break
    if kind == "host":
        kind = host_kind()
        if not kind:
            notifier.error(
                f"this platform has no service format Phantom knows: name "
                f"one explicitly ({', '.join(KINDS)})")
            return 2
    ok, reason = supported(kind)
    if not ok:
        notifier.error(reason)
        return 2

    unit_name = args.service_name or default_name(kind)
    user = not args.service_system

    if action == "uninstall":
        try:
            path = service_path(kind, unit_name, user=user)
            # hash the file WHILE it is still there, so the removal is
            # verifiable against what the install reported
            before_digest = file_digest(path)
            removed = uninstall_service(path)
        except ValueError as exc:
            # a hostile `--service-name` reaches this branch first: refusing
            # here is what keeps the flag from naming a path outside the unit
            # directory
            notifier.error(str(exc))
            return 2
        _audit_service(KIND_REMOVED, format=kind, name=unit_name, path=path,
                       digest=before_digest, user=user)
        if removed:
            notifier.success(f"service definition removed: {path}")
            if before_digest:
                notifier.info(f"the removed file's sha256 was "
                              f"{before_digest[:16]}… (compare it with what "
                              f"--install-service reported)")
        else:
            notifier.warn(f"nothing to remove: {path}")
        if kind == "schtasks":
            notifier.info(f'also remove the task itself: schtasks /delete /tn '
                          f'"{unit_name}" /f')
        elif kind == "systemd":
            prefix = "systemctl --user" if user else "sudo systemctl"
            notifier.info(f"stop it first: {prefix} disable --now "
                          f"{os.path.basename(path)}")
        else:
            notifier.info(f"unload it first: launchctl unload -w {path}")
        return 0

    if args.plan:
        notifier.error("--plan only previews a run: a service definition for "
                       "it would do nothing. Drop --plan to install the real "
                       "thing.")
        return 2
    if not targets:
        notifier.error("a service definition needs the targets to run: pass "
                       "them after --auto (e.g. `--auto 10.0.0.5 "
                       "--install-service`)")
        return 2

    command = build_service_command(args, targets)
    try:
        plan = plan_service(kind, command, working_dir=project_root(),
                            name=unit_name, user=user)
    except ValueError as exc:
        notifier.error(str(exc))
        return 2

    if action == "print":
        sys.stdout.write(plan["content"])
        return 0

    try:
        path = install_service(plan)
    except (OSError, ValueError) as exc:
        notifier.error(f"cannot write {plan['path']}: {exc}")
        return 2
    _audit_service(KIND_INSTALLED, format=kind, name=unit_name, path=path,
                   digest=plan.get("digest", ""),
                   content_digest=plan.get("content_digest", ""), user=user)
    notifier.success(f"service definition written: {path}")
    # WHAT was written, in a form the operator can check later: the invocation
    # digest identifies the exact command line, the content digest the bytes.
    notifier.info(f"this invocation: sha256 {plan.get('digest', '')[:16]}… "
                  f"— the same values are in the decision audit log")
    notifier.info(f"activate it: {plan['hint']}")
    notifier.info("the run it starts is supervised and resumes the newest "
                  "checkpoint; its restart budget is the persisted one, so a "
                  "crash loop ends with a reason instead of forever")
    return 0


def run_pentest_shell(args) -> None:
    """The classic MANUAL module shell, on the shared engagement session."""
    shell = PhantomShell()
    shell.auto_run = args.yes
    if args.profile:
        shell.load_profile(args.profile)

    # Auto-session: register this open, offer to resume the last engagement
    from phantom.utils.auto_session import auto_export, offer_resume, register_open
    register_open()
    offer_resume(quiet=args.yes)

    try:
        shell.cmdloop()
    except KeyboardInterrupt:
        console.print("\n[dim]Phantom closed.[/]\n")
        return
    finally:
        # Auto-session: persist the engagement as an encrypted .pm on EVERY
        # close path (exit, quit, double Ctrl+C) without asking.
        exported = auto_export()
        if exported:
            console.print(f"[dim]Session auto-saved: {exported}[/]")

if __name__ == "__main__":
    main()